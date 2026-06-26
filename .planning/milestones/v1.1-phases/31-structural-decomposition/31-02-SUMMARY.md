---
phase: 31
plan: 2
status: complete
started: 2026-03-28T20:15:00Z
completed: 2026-03-28T20:22:00Z
---

# Summary: 31-02 Web Layer Barrel Re-Exports and SDK Adoption

## What was built

Redirected web app files to use SDK exports from Plan 01:

1. **folder.service.ts**: `getDepth`, `calculateSubtreeDepth`, `isDescendantOf` now delegate to `@cipherbox/sdk-core`
2. **folder-helpers.ts**: `withConflictRetry` wraps SDK version with web-specific sync banner UI
3. **useSharedNavigation.ts**: Adopted SDK `ShareKeyCache`, `buildSharedWriteContext`, and `withRevocationGuard`; removed local `isForbiddenError`

All consumers compile without import changes (backward compatible).

## Key files

### Modified
- `apps/web/src/services/folder.service.ts` (tree functions delegate to SDK)
- `apps/web/src/hooks/folder-helpers.ts` (withConflictRetry wraps SDK)
- `apps/web/src/hooks/useSharedNavigation.ts` (SDK utilities adopted)

## Self-Check: PASSED
- `pnpm --filter web build` passed
- No consumer import changes needed
- ShareKeyCache TTL=60s matches original
