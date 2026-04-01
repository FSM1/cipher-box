# Phase 38: Retire deprecated web services - Context

**Gathered:** 2026-03-31
**Status:** Complete (2026-03-31, PR #422)

<domain>
## Phase Boundary

Remove `folder.service.ts` (1,059 lines) and `bin.service.ts` (971 lines) by migrating all remaining callers to `@cipherbox/sdk` methods, eliminating the deprecated service layer. Also remove the circular devDependency from `@cipherbox/crypto` on `@cipherbox/core` by refactoring the vault-ipns test to use hardcoded test vectors instead of cross-package imports.

</domain>

<decisions>
## Implementation Decisions

### Caller migration pattern

- **D-01:** Follow the established SDK migration pattern used by shared folder hooks (e.g., `useSharedWriteOps.ts`): hooks import SDK functions directly from `@cipherbox/sdk` and pass store-extracted state as explicit parameters. No adapter layer.
- **D-02:** Delete both `folder.service.ts` and `bin.service.ts`, and remove their re-exports from `services/index.ts`. Other services remain untouched.

### Utility function placement

- **D-03:** Move pure utility functions to SDK packages: path utilities (`getDepth`, `isDescendantOf`) go to `@cipherbox/sdk-core` (domain logic), `fetchAndDecryptMetadata` goes to `@cipherbox/sdk`. Keep the web app thin.

### Circular dependency fix

- **D-04:** Remove `@cipherbox/core` devDependency from `@cipherbox/crypto` by replacing the `vault-ipns.test.ts` imports with hardcoded test vectors. Pre-compute expected values from `deriveRegistryIpnsKeypair`/`initializeVault`, embed as constants. Test verifies domain separation against static values.

### Claude's Discretion

- Per-hook migration order and grouping
- Whether to batch all caller migrations in one plan or split by service
- Exact test vector values (compute once, embed)

</decisions>

<canonical_refs>

## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Deprecated services (to be removed)

- `apps/web/src/services/folder.service.ts` — 1,059 LOC, folder CRUD with Zustand store access
- `apps/web/src/services/bin.service.ts` — 971 LOC, recycle bin operations with store access
- `apps/web/src/services/index.ts` — barrel file re-exporting both services

### SDK equivalents (migration targets)

- `packages/sdk/src/bin/index.ts` — SDK bin operations (extracted from bin.service.ts)
- `packages/sdk-core/src/folder/index.ts` — SDK folder operations (extracted from folder.service.ts)
- `packages/sdk/src/index.ts` — SDK public API surface

### Established migration pattern

- `apps/web/src/hooks/useSharedWriteOps.ts` — reference implementation: imports SDK functions, passes explicit params
- `apps/web/src/lib/sdk-provider.ts` — CipherBoxClient singleton lifecycle (getSdkClient pattern)

### Callers to migrate

- `apps/web/src/hooks/folder-helpers.ts` — imports folderService.\*
- `apps/web/src/hooks/useFileOperations.ts` — imports folderService.\*
- `apps/web/src/hooks/useFileVersions.ts` — imports folderService.\*
- `apps/web/src/hooks/useFolderMutations.ts` — imports folderService.\*
- `apps/web/src/hooks/useFolderNavigation.ts` — imports loadFolder from folder.service
- `apps/web/src/hooks/useAuth.ts` — imports initializeBin from bin.service
- `apps/web/src/hooks/useBin.ts` — imports initializeBin, purgeExpired from bin.service
- `apps/web/src/components/file-browser/useFileBrowserActions.ts` — imports fetchAndDecryptMetadata
- `apps/web/src/components/file-browser/MoveDialog.tsx` — imports getDepth, isDescendantOf

### Circular dependency

- `packages/crypto/package.json` — devDependencies includes @cipherbox/core (line 33)
- `packages/crypto/src/__tests__/vault-ipns.test.ts` — imports deriveRegistryIpnsKeypair, initializeVault from @cipherbox/core

</canonical_refs>

<code_context>

## Existing Code Insights

### Reusable Assets

- `CipherBoxClient` singleton via `getSdkClient()` — centralized SDK access point
- `@cipherbox/sdk` bin module — already extracted, mirrors bin.service.ts functions with explicit params
- `@cipherbox/sdk-core` folder module — already extracted, mirrors folder.service.ts functions with explicit params
- `useSharedWriteOps.ts` — proven migration pattern for SDK integration in hooks

### Established Patterns

- Hooks extract state from Zustand stores (`useAuthStore`, `useFolderStore`, `useBinStore`) and pass to SDK
- `withConflictRetry` wrapper from `@cipherbox/sdk` used for optimistic concurrency
- `apiAxios` injected into SDK client for shared HTTP instance

### Integration Points

- `services/index.ts` barrel file — needs folder.service and bin.service exports removed
- Zustand stores (`folder.store.ts`, `bin.store.ts`) — already import types from `@cipherbox/sdk`, no changes expected
- Other services in `services/` directory (share, device-registry, etc.) — remain untouched

</code_context>

<specifics>
## Specific Ideas

- Follow established patterns from hooks that already migrated to SDK (e.g., useSharedWriteOps.ts)
- No new abstraction layers — direct SDK imports in hooks

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

_Phase: 38-retire-deprecated-web-services_
_Context gathered: 2026-03-31_
