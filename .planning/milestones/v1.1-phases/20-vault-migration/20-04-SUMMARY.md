---
phase: 20-vault-migration
plan: 04
subsystem: auth
tags: [vault, blob-v2, login-flow, lazy-migration, ipns, recovery-tool, ecies, zero-knowledge]

# Dependency graph
requires:
  - phase: 20-vault-migration
    provides: 'Plan 01 vault blob v2 format (serialize/deserialize/detect), Plan 02 API migration endpoint + nullable columns'
provides:
  - 'Web login flow reads rootFolderKey from IPFS v2 blob for migrated users (PATH A)'
  - 'Non-blocking lazy migration for non-migrated users writes v2 blob + publishes IPNS + calls /vault/migrate (PATH B)'
  - 'Silent DB fallback when IPFS v2 read fails for migrated users'
  - 'Recovery tool parses v2 blobs from IPFS independently of CipherBox API'
  - 'New vault init omits encryptedRootIpnsPrivateKey (HKDF derivation canonical)'
affects: [recovery-tool, desktop-vault, staging-deploy]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - 'Non-blocking migration via fire-and-forget async IIFE in login flow'
    - 'Silent DB fallback for IPFS failures on migrated users (console.warn, no throw)'
    - 'Recovery tool uses gateway /ipns/ HEAD request for IPNS resolution without API dependency'
    - 'V2 blob version detection via first-byte check (inline in standalone recovery HTML)'

key-files:
  created: []
  modified:
    - apps/web/src/hooks/useAuth.ts
    - apps/web/public/recovery.html
    - apps/web/src/services/folder.service.ts
    - packages/core/src/vault/blob.ts
    - packages/core/src/index.ts
    - packages/sdk-core/src/folder/index.ts

key-decisions:
  - 'Recovery tool IPNS resolution uses gateway /ipns/ HEAD request with redirect following, avoiding dependency on delegated routing or CipherBox API'
  - 'VaultExportDto crypto fields made nullable (string | null) to reflect migrated user state where DB columns are NULLed'
  - 'fetchAndDecryptMetadata updated to handle both v1 JSON and v2 binary blobs transparently'

patterns-established:
  - 'PATH A / PATH B branching on migratedAt for login flow'
  - 'Non-blocking migration with retry-on-next-login for resilience'
  - 'Standalone recovery tool inlines all crypto logic (no npm imports)'

requirements-completed: [VAULT-02, VAULT-03, VAULT-05]

# Metrics
duration: 45min
completed: 2026-03-24
---

# Phase 20 Plan 04: Web Client v2 Blob Login Summary

**Web login reads rootFolderKey from IPFS v2 blob for migrated users, triggers non-blocking lazy migration for non-migrated users, and recovery tool parses v2 blobs independently via IPFS gateway**

## Performance

- **Duration:** ~45 min (including UAT verification and 10 fix commits)
- **Started:** 2026-03-24 (prior session)
- **Completed:** 2026-03-24
- **Tasks:** 3 (2 auto + 1 human-verify checkpoint)
- **Files modified:** 15

## Accomplishments

- Login flow branches on `migratedAt`: migrated users read rootFolderKey from IPFS v2 blob, non-migrated users decrypt from DB and trigger lazy migration
- Lazy migration writes v2 blob to IPFS, publishes IPNS record with optimistic concurrency, and calls POST /vault/migrate -- all non-blocking with retry-on-next-login
- Recovery tool supports both export-based and IPFS-direct recovery paths with inline v2 blob parsing
- fetchAndDecryptMetadata in folder.service.ts updated to handle v2 blobs transparently (critical for folder sync after migration)
- End-to-end UAT confirmed: migration sets migratedAt, NULLs crypto columns, and subsequent login reads from IPFS

## Task Commits

Each task was committed atomically:

1. **Task 1: Update initializeOrLoadVault for v2 blob read and migration trigger** - `014aa1a36` (feat)
2. **Task 2: Update recovery tool for v2 blob parsing** - `ee001c7a7` (feat)
3. **Task 3: Human verification checkpoint** - approved after UAT

**Fix commits during UAT verification:**

- `d9c5de022` - fix(20): address high-priority security review findings
- `09623b206` - refactor(20): eliminate redundant crypto operations
- `f0940e80c` - fix(20): handle v2 blob in fetchAndDecryptMetadata
- `65b255bb0` - chore(20): remove debug logging, resolve debug session
- `bf5db43e3` - fix(20): prevent fetchFromIpfs returning undefined
- `880c806dc` - fix(20): fix recovery tool IPNS resolution with delegated routing
- `1dbb8807d` - fix(20): recovery tool falls back to CipherBox API for IPNS resolution
- `d4ed12b65` - fix(20): recovery tool IPNS fallback uses configured gateway + Kubo API
- `9c8dcd5b8` - fix(20): recovery tool uses gateway /ipns/ path for direct resolution
- `66dcbb4e4` - fix(20): recovery tool resolves IPNS via gateway /ipns/ HEAD request

## Files Created/Modified

- `apps/web/src/hooks/useAuth.ts` - PATH A (migrated: IPFS v2 read) + PATH B (non-migrated: DB decrypt + lazy migration trigger)
- `apps/web/public/recovery.html` - v2 blob parsing, IPFS-direct recovery UI, gateway /ipns/ IPNS resolution
- `apps/web/src/services/folder.service.ts` - fetchAndDecryptMetadata handles v2 blobs (detectBlobVersion + deserialize)
- `packages/core/src/vault/blob.ts` - Minor adjustments to blob module
- `packages/core/src/index.ts` - Updated exports
- `packages/sdk-core/src/folder/index.ts` - Updated folder operations for v2 blob compatibility
- `apps/desktop/src-tauri/src/api/types.rs` - VaultExportDto nullable fields
- `apps/desktop/src-tauri/src/commands/vault.rs` - Vault fetch adjustments
- `apps/desktop/src-tauri/src/crypto/vault_blob.rs` - Cross-platform blob adjustments
- `apps/desktop/src-tauri/src/fuse/mod.rs` - FUSE mount v2 publish support

## Decisions Made

- Recovery tool IPNS resolution evolved through 5 iterations to settle on gateway `/ipns/` HEAD request with redirect following -- most reliable approach that works without CipherBox API or delegated routing dependency
- fetchAndDecryptMetadata updated to transparently handle both v1 (raw JSON) and v2 (binary blob with header) formats, so folder sync works immediately after migration
- Debug logging removed after UAT session to avoid key material exposure in production
- Security review findings addressed: redundant crypto operations eliminated, fetchFromIpfs hardened against undefined returns

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] fetchAndDecryptMetadata did not handle v2 blobs**

- **Found during:** Task 3 (UAT verification)
- **Issue:** After migration, folder sync failed because fetchAndDecryptMetadata expected v1 JSON but received v2 binary blob
- **Fix:** Added detectBlobVersion check and deserializeVaultBlobV2 extraction before AES-GCM decryption
- **Files modified:** apps/web/src/services/folder.service.ts
- **Committed in:** f0940e80c

**2. [Rule 1 - Bug] fetchFromIpfs returned undefined on non-404 failures**

- **Found during:** Task 3 (UAT verification)
- **Issue:** Non-404 IPFS fetch errors silently returned undefined instead of throwing
- **Fix:** Added explicit throw for non-404 error responses
- **Files modified:** apps/web/src/lib/api/ipfs.ts
- **Committed in:** bf5db43e3

**3. [Rule 2 - Security] Debug logging exposed sensitive operations**

- **Found during:** Task 3 (UAT verification)
- **Issue:** Debug console.log statements from development session left in useAuth.ts
- **Fix:** Removed all debug logging
- **Files modified:** apps/web/src/hooks/useAuth.ts
- **Committed in:** 65b255bb0

**4. [Rule 2 - Security] Redundant crypto operations**

- **Found during:** Task 3 (security review)
- **Issue:** Redundant unwrapKey/wrapKey calls in migration path
- **Fix:** Eliminated redundant operations
- **Files modified:** apps/web/src/hooks/useAuth.ts
- **Committed in:** 09623b206

**5. [Rule 1 - Bug] Recovery tool IPNS resolution failures (5 iterations)**

- **Found during:** Task 3 (UAT verification)
- **Issue:** Recovery tool could not resolve IPNS names -- delegated routing, CipherBox API fallback, Kubo API, and direct gateway attempts all had issues
- **Fix:** Settled on gateway `/ipns/` HEAD request with redirect following, which reliably resolves to CID
- **Files modified:** apps/web/public/recovery.html
- **Committed in:** 880c806dc, 1dbb8807d, d4ed12b65, 9c8dcd5b8, 66dcbb4e4

---

**Total deviations:** 5 auto-fixed (3 bugs, 2 security/critical)
**Impact on plan:** All fixes necessary for correct end-to-end operation. No scope creep -- all issues directly caused by plan changes or discovered during mandatory UAT.

## Issues Encountered

- Recovery tool IPNS resolution required 5 iterative fixes. Delegated routing was unreliable, CipherBox API fallback added complexity, and ultimately the simplest approach (gateway `/ipns/` HEAD request) proved most robust. This is a pre-existing infrastructure limitation with IPNS DHT propagation.
- Subfolder recovery is limited by IPNS DHT propagation for subfolder IPNS names. This is a pre-existing infrastructure limitation, not caused by phase 20 changes. Root-level recovery works reliably.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Phase 20 (Vault Migration) is now complete -- all 4 plans executed
- Server stores zero crypto material for migrated users (true zero-knowledge relay achieved)
- Ready for Phase 21 (BYO-IPFS Node Support) which depends on stable IPNS (Phase 19, complete)
- Recovery tool independence verified for v2 blobs (root-level; subfolder limited by DHT propagation)
- Todo captured for future E2E test coverage of recovery tool v2 paths

## Self-Check: PASSED

- All key files exist on disk (useAuth.ts, recovery.html, folder.service.ts, 20-04-SUMMARY.md)
- All task commits found in git log (014aa1a36, ee001c7a7)
- All key fix commits found in git log (f0940e80c, 66dcbb4e4)

---

_Phase: 20-vault-migration_
_Completed: 2026-03-24_
