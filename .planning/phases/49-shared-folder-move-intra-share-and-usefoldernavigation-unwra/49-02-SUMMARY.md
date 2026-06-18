---
phase: 49-shared-folder-move-intra-share-and-usefoldernavigation-unwra
plan: 02
subsystem: ui
tags: [react, sdk, ecies, ipns, hooks, folder-navigation]

requires:
  - phase: none
    provides: SDK ensureFolderLoaded method (existing)

provides:
  - useFolderNavigation.navigateTo delegates ECIES unwrap to SDK via ensureFolderLoaded with 3x/2s retry wrapper

affects:
  - 49-03-and-beyond (shared folder move plans using same hook)

tech-stack:
  added: []
  patterns:
    - 'SDK-delegate pattern: web hook calls ensureFolderLoaded, SDK owns ECIES unwrap + IPNS resolve + decrypt'
    - 'Buffer-clone safety: new Uint8Array(state.folderKey) before storing in React state (mirrors SharedFolderTree.set)'
    - 'IPNS-propagation retry: thin 3x/2s wrapper at web layer (ensureFolderLoaded has no retry)'

key-files:
  created: []
  modified:
    - apps/web/src/hooks/useFolderNavigation.ts

key-decisions:
  - 'Keep @internal on ensureFolderLoaded — call directly, no new public alias'
  - 'Remove vaultKeypair guard (now internal to SDK); ensureFolderLoaded uses internalVaultKeypair'
  - 'latestNavTarget guard placed at top of each retry iteration AND after the full loop'
  - 'Do not read state.ipnsKeypair.publicKey — empty Uint8Array for tree-walked folders'

requirements-completed: [REQ-4]

duration: 15min
completed: 2026-06-18
---

# Phase 49 Plan 02: useFolderNavigation Unwrap Consolidation Summary

**Collapsed duplicated ECIES unwrap + IPNS-resolve + decrypt in useFolderNavigation onto SDK's ensureFolderLoaded, preserving 3x/2s retry and cloning key buffers into FolderNode**

## Performance

- **Duration:** ~15 min
- **Started:** 2026-06-18T03:25:00Z
- **Completed:** 2026-06-18T03:40:00Z
- **Tasks:** 1
- **Files modified:** 1

## Accomplishments

- Removed 62 lines of hand-rolled ECIES unwrap, IPNS record resolve, and folder-metadata decrypt from `useFolderNavigation.navigateTo`
- Single source of truth for folder-key unwrap now lives in `client.ensureFolderLoaded`
- Preserved the 3x/2s IPNS-propagation retry via thin web-side loop (ensureFolderLoaded returns null immediately, no retry)
- `latestNavTarget.current` cancellation guard preserved at each retry iteration and after the loop
- Key buffers cloned into FolderNode with `new Uint8Array(state.folderKey)` — survives `client.destroy()` zeroing on logout

## Task Commits

1. **Task 1: Replace useFolderNavigation unwrap block with ensureFolderLoaded + retry wrapper** - `51ac4a2ec` (refactor)

**Plan metadata:** (see final commit below)

## Files Created/Modified

- `apps/web/src/hooks/useFolderNavigation.ts` - Replaced ~60-line manual unwrap block with ensureFolderLoaded delegation; removed dead imports (unwrapKey, hexToBytes, fetchAndDecryptMetadata, resolveIpnsRecord, useAuthStore)

## Decisions Made

- Keep `@internal` on `ensureFolderLoaded` — call directly from web (intra-monorepo consumer), no boilerplate alias needed
- Removed the now-redundant `vaultKeypair` guard (SDK uses `internalVaultKeypair` internally)
- Extra post-loop guard `if (latestNavTarget.current !== targetFolderId) return` added after all retry awaits per apps/web async-ref-safety rule

## Deviations from Plan

None — plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- useFolderNavigation unwrap consolidation complete (REQ-4 done)
- Remaining Phase 49 plans (shared folder move SDK + UI) unblocked — this plan was Wave 1, independent of move work

---

_Phase: 49-shared-folder-move-intra-share-and-usefoldernavigation-unwra_
_Completed: 2026-06-18_
