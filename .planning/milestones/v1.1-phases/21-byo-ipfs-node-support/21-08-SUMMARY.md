---
phase: 21-byo-ipfs-node-support
plan: 08
subsystem: storage
tags: [byo-ipfs, pinning, sdk, migration, tee]

# Dependency graph
requires:
  - phase: 21-03
    provides: PinningProvider interface (KuboProvider, PsaProvider) and pinWithMode logic
  - phase: 21-05
    provides: BYO config encrypted IPNS storage and StorageTab UI
provides:
  - SDK client initialized with BYO pinning config at login time
  - Runtime reconfigurePinning for mid-session config changes
  - Source CID unpin after verified migration transfer in TEE worker
affects: [21-09, 21-10, 21-11]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - loadByoConfig helper pattern for async config load with graceful degradation
    - _lastConfig module-level state for SDK client reconfiguration
    - Best-effort source unpin after verified CID transfer

key-files:
  created: []
  modified:
    - apps/web/src/hooks/useAuth.ts
    - apps/web/src/lib/sdk-provider.ts
    - apps/web/src/components/settings/StorageTab.tsx
    - apps/web/src/hooks/useDropUpload.ts
    - tee-worker/src/services/migration-worker.ts
    - packages/sdk/src/index.ts

key-decisions:
  - 'BYO config loaded at login via IPNS resolve with graceful fallback to cipherbox-only mode'
  - 'SDK client recreated on reconfigurePinning (acceptable cost for infrequent Settings saves)'
  - 'Source unpin is best-effort and non-fatal -- destination CID verified before attempting'
  - 'Duplicate file uploads always route through CipherBox relay for replacement dialog staging'

patterns-established:
  - 'loadByoConfig pattern: derive IPNS keypair, resolve, fetch, decrypt, return PinningConfig or undefined'
  - 'reconfigurePinning pattern: destroy + recreate client preserving _lastConfig'

requirements-completed: [BYO-02, BYO-03]

# Metrics
duration: 5min
completed: 2026-03-25
---

# Phase 21 Plan 08: BYO Pinning Config Wiring Summary

**SDK client initialized with BYO pinning config at login, StorageTab saves trigger runtime reconfiguration, and TEE migration worker unpins source CIDs after verified transfer**

## Performance

- **Duration:** 5 min
- **Started:** 2026-03-25T00:46:32Z
- **Completed:** 2026-03-25T00:51:40Z
- **Tasks:** 2
- **Files modified:** 6

## Accomplishments

- SDK client now loads BYO pinning config from encrypted IPNS entry at login time, enabling pinWithMode to activate correct mode for all uploads
- Runtime reconfigurePinning in sdk-provider.ts allows StorageTab saves to update the active SDK client without requiring re-login
- TEE migration worker unpins CIDs from source provider after verified CID transfer, preventing orphaned pins on the source
- Exported PinningConfig type from @cipherbox/sdk package for consumer use

## Task Commits

Each task was committed atomically:

1. **Task 1: Wire BYO config into SDK client initialization and add runtime reconfiguration** - `ed8ac42fd` (feat)
2. **Task 2: Add source unpin after verified migration transfer in TEE worker** - `47460a049` (feat)

## Files Created/Modified

- `apps/web/src/hooks/useAuth.ts` - Added loadByoConfig helper and pinningConfig injection into initSdkClient
- `apps/web/src/lib/sdk-provider.ts` - Added \_lastConfig state, reconfigurePinning() export
- `apps/web/src/components/settings/StorageTab.tsx` - Calls reconfigurePinning after save
- `apps/web/src/hooks/useDropUpload.ts` - Added explanatory comment for duplicate file CipherBox relay behavior
- `tee-worker/src/services/migration-worker.ts` - Added unpinFromProvider (Kubo + PSA) and best-effort source unpin call
- `packages/sdk/src/index.ts` - Exported PinningConfig type

## Decisions Made

- **Graceful degradation for BYO config**: loadByoConfig wraps entire body in try/catch, returning undefined on any failure (IPNS resolve, fetch, decrypt). This means users without BYO config or with corrupted config seamlessly fall back to cipherbox-only mode.
- **Client recreation for reconfiguration**: reconfigurePinning destroys and recreates the CipherBoxClient. While heavyweight, config changes are rare (only on Settings save) and this approach is simpler than adding mutable pinning state to the client.
- **Best-effort source unpin**: The unpin call is inside a try/catch that silently swallows errors. The CID is already verified on the destination, so failed unpins only leave orphaned pins (not data loss).
- **CipherBox protocol guard**: Source unpins skip cipherbox protocol since those are handled by the API-side MigrationProcessor which has direct IPFS access.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Exported PinningConfig from @cipherbox/sdk package index**

- **Found during:** Task 1 (SDK client initialization)
- **Issue:** PinningConfig type defined in packages/sdk/src/types.ts but not exported from package index, causing TS2305 import error in useAuth.ts and sdk-provider.ts
- **Fix:** Added PinningConfig to the type export in packages/sdk/src/index.ts
- **Files modified:** packages/sdk/src/index.ts
- **Verification:** pnpm --filter web exec tsc --noEmit passes cleanly
- **Committed in:** ed8ac42fd (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (1 blocking)
**Impact on plan:** Necessary export for type safety. No scope creep.

## Issues Encountered

None

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- BYO pinning config is now wired end-to-end: load at login, reconfigure on save, unpin after migration
- Ready for remaining gap closure plans (21-09 through 21-11)

---

## Self-Check: PASSED

All 6 modified files verified on disk. Both task commits (ed8ac42fd, 47460a049) found in git log.

---

_Phase: 21-byo-ipfs-node-support_
_Completed: 2026-03-25_
