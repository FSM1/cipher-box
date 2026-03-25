---
phase: 20-vault-migration
plan: 06
subsystem: auth
tags: [vault, ipfs, v2-blob, dead-code-removal, desktop, recovery]

# Dependency graph
requires:
  - phase: 20-05
    provides: Simplified API with zero-crypto vault schema (no crypto columns, no migrate endpoint)
provides:
  - Web login with single IPFS-only v2 blob read path (no DB fallback)
  - Web new user init publishes v2 blob to IPFS before API registration
  - Desktop Rust vault types without crypto fields or migrated_at
  - Desktop fetch_and_decrypt_vault with single IPFS-only path
  - Recovery tool export-file path with v2-aware messaging
affects: [phase-23-rust-sdk]

# Tech tracking
tech-stack:
  added: []
  patterns: [IPFS-only vault key storage, v2 blob publish on new user init]

key-files:
  created: []
  modified:
    - apps/web/src/hooks/useAuth.ts
    - apps/desktop/src-tauri/src/api/types.rs
    - apps/desktop/src-tauri/src/commands/vault.rs
    - apps/web/public/recovery.html

key-decisions:
  - 'New web user init publishes v2 blob to IPFS with encryptFolderMetadata for empty metadata before calling API initVault'
  - 'Desktop InitVaultRequest reduced to ownerPublicKey + rootIpnsName only'
  - 'Recovery tool export-file null-key check updated to reflect permanent v2 format (not just migrated state)'

patterns-established:
  - 'IPFS-only vault key storage: all clients treat v2 blob as sole source of rootFolderKey'

requirements-completed: [VAULT-01, VAULT-02, VAULT-03, VAULT-04, VAULT-05, VAULT-06]

# Metrics
duration: 6min
completed: 2026-03-24
---

# Phase 20 Plan 06: Client Dead Code Removal Summary

**Removed all migration/DB-fallback code from web, desktop, and recovery tool -- clients now treat IPFS v2 blob as sole source of rootFolderKey**

## Performance

- **Duration:** 6 min
- **Started:** 2026-03-24T03:15:58Z
- **Completed:** 2026-03-24T03:22:17Z
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments

- Simplified web useAuth.ts from 116 lines of dual-path vault logic to 50 lines of IPFS-only v2 blob reads
- New web user init now publishes v2 blob (with encrypted empty folder metadata) to IPFS before registering vault with API, matching desktop behavior
- Removed all `as unknown as string` type casts, dead imports (`decryptVaultKeys`, `encryptVaultKeys`, `vaultControllerMigrateVault`, `hexToBytes`)
- Desktop Rust `InitVaultRequest` reduced from 4 fields to 2, `VaultResponse` reduced from 5 fields to 2
- Desktop `fetch_and_decrypt_vault` simplified from 65 lines of dual-path logic to 35 lines of IPFS-only path
- Recovery tool export-file message updated to reflect permanent v2 vault format

## Task Commits

Each task was committed atomically:

1. **Task 1: Simplify web useAuth.ts** - `a48a41b27` (feat)
2. **Task 2: Simplify desktop Rust vault code and recovery tool** - `cd7bcd39b` (feat)

## Files Created/Modified

- `apps/web/src/hooks/useAuth.ts` - Simplified to IPFS-only v2 blob read + v2 blob publish on new user init
- `apps/desktop/src-tauri/src/api/types.rs` - Removed crypto fields from InitVaultRequest and VaultResponse
- `apps/desktop/src-tauri/src/commands/vault.rs` - Removed dual-path logic, IPFS-only fetch_and_decrypt_vault
- `apps/web/public/recovery.html` - Updated export-file null-key message for v2 format

## Decisions Made

- New web user init uses `encryptFolderMetadata` from `@cipherbox/core` to create empty metadata, then JSON.stringifies the `{ iv, data }` result and encodes to bytes for the v2 blob (matching the format expected by `decryptFolderMetadata`)
- Used `as BlobPart` cast for `Uint8Array` to `Blob` constructor (consistent with existing codebase pattern for TypeScript strict mode compatibility)
- Recovery tool export-file legacy decryption path left intact for backward compatibility with pre-migration export files

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] TypeScript Uint8Array BlobPart cast**

- **Found during:** Task 1 (web build)
- **Issue:** `new Blob([v2Blob])` fails TypeScript strict check because `Uint8Array.buffer` type includes `SharedArrayBuffer`
- **Fix:** Added `as BlobPart` cast (consistent with existing codebase pattern)
- **Files modified:** apps/web/src/hooks/useAuth.ts
- **Verification:** `pnpm --filter web build` exits 0
- **Committed in:** a48a41b27 (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (1 blocking)
**Impact on plan:** Trivial TypeScript cast consistent with existing codebase patterns. No scope creep.

## Issues Encountered

None

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Phase 20 (vault-migration) is now complete -- all 6 plans executed
- All clients (web, desktop, recovery tool) treat v2 blob as sole vault key format
- API stores only ownerPublicKey and rootIpnsName (zero-crypto schema)
- Ready for Phase 23 (Rust SDK Extraction) which will further clean up duplicated crypto logic

---

## Self-Check: PASSED

All files exist, all commits verified, SUMMARY.md created.

---

_Phase: 20-vault-migration_
_Completed: 2026-03-24_
