---
phase: 17-recycle-bin
plan: 02
subsystem: web, crypto
tags: [zustand, ipns, ecies, recycle-bin, soft-delete, restore]

# Dependency graph
requires:
  - phase: 17-01
    provides: Bin metadata types, HKDF derivation, ECIES encrypt/decrypt, GET /vault/config endpoint
provides:
  - Zustand bin store for tracking soft-deleted items
  - Bin service with full IPNS lifecycle (initialize, add, restore, permanent delete, empty, purge)
  - useBin React hook for bin operations with loading/error state
  - Soft-delete flow (handleDelete/handleDeleteItems call addToBin instead of unpinFromIpfs)
  - folder.service returns removedChild from deleteFolder/deleteFileFromFolder
  - Bin initialization on login and cleanup on logout via useAuth
affects: [17-03 web UI bin page, 17-04 desktop FUSE soft-delete, 17-05 integration testing]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - 'Bin service follows device-registry.service pattern: derive IPNS keypair, resolve/create, encrypt/publish'
    - 'Fire-and-forget addToBin from delete flow (non-blocking, log on error)'
    - 'Recursive parent restore with max depth 5 to prevent infinite loops'
    - 'TEE enrollment on first bin write (session-scoped flag)'

key-files:
  created:
    - apps/web/src/stores/bin.store.ts
    - apps/web/src/services/bin.service.ts
    - apps/web/src/hooks/useBin.ts
  modified:
    - apps/web/src/services/folder.service.ts
    - apps/web/src/hooks/useFolderMutations.ts
    - apps/web/src/hooks/useAuth.ts

key-decisions:
  - 'Implemented all bin service operations in single task (no stub-then-fill split)'
  - 'addToBin is fire-and-forget from delete flow to avoid blocking UI'
  - 'Folder size stored as 0 in bin entries (resolved on permanent delete)'
  - 'CID cleanup resolves file IPNS metadata to find content CID and size for quota'
  - 'Recursive folder CID cleanup uses loaded folder store data when available'
  - 'Retention config fetched from API on login and stored in bin store'

patterns-established:
  - 'buildFolderPath helper for breadcrumb-style path construction from folder tree'
  - 'Batch delete captures removedChildren before filtering for bin integration'

# Metrics
duration: 9min
completed: 2026-03-04
---

# Phase 17 Plan 02: Bin Store, Service, and Delete Flow Rewiring Summary

**Zustand bin store with full IPNS lifecycle service (initialize, add, restore, permanent delete, purge), soft-delete integration replacing unpinFromIpfs in useFolderMutations, and bin initialization on login via useAuth**

## Performance

- **Duration:** 9 min
- **Started:** 2026-03-04T01:25:26Z
- **Completed:** 2026-03-04T01:34:15Z
- **Tasks:** 3 (Tasks 1-2 combined, Task 3 separate)
- **Files modified:** 6

## Accomplishments

- Created complete bin store and bin service following device-registry.service.ts IPNS patterns: HKDF derivation, ECIES encrypt/decrypt, IPFS pin, IPNS publish with TEE enrollment
- Rewired delete flow: `handleDelete` and `handleDeleteItems` now call `addToBin` (fire-and-forget) instead of `unpinFromIpfs`, preserving CIDs for recovery
- Full restore flow with recursive parent restore (max depth 5), name collision handling (" (restored)" suffix), and fallback to root folder
- Permanent delete with CID cleanup: resolves file IPNS metadata for content CID, unpins, updates quota via `removeUsage`
- Auto-purge of expired entries triggered on bin load via `purgeExpired`
- Bin initialized on login (fire-and-forget), retention config fetched from API, bin state cleared on both logout paths

## Task Commits

Each task was committed atomically:

1. **Task 1+2: Create bin store and bin service** - `6f4f10f96` (feat)
2. **Task 3: Rewire delete flow, create useBin hook, wire useAuth** - `e521e3731` (feat)

## Files Created/Modified

- `apps/web/src/stores/bin.store.ts` - Zustand store: entries, loading, sequenceNumber, retentionDays, CRUD actions
- `apps/web/src/services/bin.service.ts` - Full bin lifecycle: initializeBin, addToBin, restoreFromBin, permanentlyDelete, emptyBin, purgeExpired
- `apps/web/src/hooks/useBin.ts` - React hook wrapping bin service with loading/error state, daysRemaining helper
- `apps/web/src/services/folder.service.ts` - deleteFolder/deleteFileFromFolder now return `removedChild` for bin integration
- `apps/web/src/hooks/useFolderMutations.ts` - Delete flow rewired: addToBin replaces unpinFromIpfs, buildFolderPath helper added
- `apps/web/src/hooks/useAuth.ts` - initializeBin on login, vaultConfig fetch for retention, clearBin on both logout paths

## Decisions Made

- Combined Tasks 1 and 2 into a single commit since all bin service operations (including restore, permanent delete, empty, purge) were implemented together without stubs. This was simpler and avoided unnecessary interim state.
- `addToBin` is fire-and-forget from the delete flow: folder metadata is already updated, bin write is best-effort. If bin publish fails, the item is deleted from the folder tree but not tracked in bin (acceptable for v1).
- Folder size in bin entries is stored as 0 (not resolved at delete time). Size is resolved from file IPNS metadata only at permanent delete time when CIDs need unpinning.
- Used dynamic import for `folder.service` in `bin.service.ts` `restoreFromBin` to break circular dependency (bin.service imports from folder.service, but restore needs to call `updateFolderMetadata`).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed require() lint error**

- **Found during:** Task 1 (bin service creation)
- **Issue:** Used `require('../stores/vault.store')` in `getRootFolder` which violated `@typescript-eslint/no-require-imports` rule
- **Fix:** Changed to top-level `import { useVaultStore }` from `'../stores/vault.store'`
- **Files modified:** `apps/web/src/services/bin.service.ts`
- **Verification:** eslint passes, build succeeds
- **Committed in:** `6f4f10f96`

**2. [Rule 1 - Bug] Fixed implicit any type in buildFolderPath**

- **Found during:** Task 3 (useFolderMutations modification)
- **Issue:** TypeScript TS7022 error: `folder` implicitly has type `any` because it references itself in its own initializer
- **Fix:** Added explicit type annotation `const folder: FolderNode | undefined = folders[currentId]`
- **Files modified:** `apps/web/src/hooks/useFolderMutations.ts`
- **Verification:** tsc compiles without errors
- **Committed in:** `e521e3731`

---

**Total deviations:** 2 auto-fixed (2 bugs)
**Impact on plan:** Both fixes necessary for compilation. No scope creep.

## Issues Encountered

None

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Bin store, service, and hooks ready for UI consumption (Plan 03: /bin route with flat list view)
- Delete flow fully rewired to soft-delete -- all existing delete UI now writes to bin
- Retention config available in bin store for "X days remaining" display
- No blockers for Plan 03 (web UI), Plan 04 (desktop FUSE), or Plan 05 (integration)

---

_Phase: 17-recycle-bin_
_Completed: 2026-03-04_
