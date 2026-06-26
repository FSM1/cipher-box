# Phase 31: Structural Decomposition - Context

**Gathered:** 2026-03-28 (assumptions mode + discussion)
**Status:** Ready for planning

<domain>
## Phase Boundary

Monolithic files exceeding 900 lines are decomposed by migrating trapped business logic to the SDK layer and leaving React hooks as thin UI wrappers. This is an SDK-first decomposition, not a web-only split. All existing E2E tests must pass identically before and after.

</domain>

<decisions>
## Implementation Decisions

### Strategy: SDK-First Decomposition

- **D-01:** Business logic currently trapped in web app hooks/services is migrated DOWN to `@cipherbox/sdk` or `@cipherbox/sdk-core`. React hooks become thin wrappers that manage UI state and delegate to SDK functions.
- **D-02:** Framework-agnostic logic (tree validation, error handling, context building, key caching, conflict retry) moves to SDK. React-specific concerns (Zustand store management, polling intervals, breadcrumbs, dialog state) stay in web hooks.
- **D-03:** Barrel re-exports from original file paths preserve backward compatibility during migration. Consuming files should NOT need import path changes.

### SDK Migrations

#### Tree Validation Utilities → `packages/sdk-core/src/folder/tree.ts` (new)

- **D-04:** Extract `getDepth()`, `isDescendantOf()`, `calculateSubtreeDepth()` from `folder.service.ts` into SDK-core. These are pure tree traversal utilities with zero framework dependencies. Used by `useFolderMutations.ts` for move/create validation.

#### Error & Retry Utilities → `packages/sdk/src/error.ts` (new)

- **D-05:** Extract `isForbiddenError()` and `withRevocationGuard()` from `useSharedNavigation.ts` into SDK. These are pure error-handling logic with no React dependency.
- **D-06:** Refactor `withConflictRetry()` (from `folder-helpers.ts`) to SDK with a callback pattern: `withConflictRetry(operation, resync)` where `resync` is a callback the hook provides (wrapping Zustand store access). Eliminates direct Zustand coupling in the retry logic.

#### Shared Write Context → `packages/sdk/src/share/context.ts` (new)

- **D-07:** Extract `buildSharedWriteCtx()` from `useSharedNavigation.ts` into SDK as a utility that takes explicit params (keys, folder state, ipnsName) and returns `SharedWriteContext`. Currently couples hook state to SDK context creation.

#### Share Key Cache → `packages/sdk/src/share/key-cache.ts` (new)

- **D-08:** Extract the share key caching with TTL logic from `useSharedNavigation.ts` into SDK. The cache is business logic (key management), not UI concern.

#### Bin Expiration → `packages/sdk/src/bin/index.ts` (extend)

- **D-09:** Migrate `purgeExpired()` from `bin.service.ts` to SDK. Takes bin state + retention config as params instead of reading Zustand directly.

#### File Registration → `packages/sdk/src/client.ts` (extend)

- **D-10:** Migrate `addFileToFolder()` / `replaceFileInFolder()` logic from `folder.service.ts` into SDK client. File registration (create FilePointer, batch IPNS publish) is core SDK work currently manual in the web layer.

### Web Layer Cleanup

#### useSharedNavigation.ts (1199 → ~500 lines)

- **D-11:** After SDK migrations (D-05 through D-08), the hook shrinks to: share pagination + navigation state + breadcrumbs + polling + thin write handler wrappers that call SDK functions. Split remaining into 2 hooks if still >400 lines:
  - `useSharedNavigationState` — share loading, folder traversal, sync polling
  - `useSharedWriteOps` — thin wrappers calling SDK with UI state management

#### FileBrowser.tsx (964 → container + presentational)

- **D-12:** Extract ~600 lines of handler logic into `useFileBrowserActions` hook. JSX (~365 lines) becomes presentational receiving handlers via props.

#### SharedFileBrowser.tsx (943 → container + presentational)

- **D-13:** Same container/presentational split. Adopt `useDialogState` hook (already used by FileBrowser) for 6 manually managed dialog states, eliminating ~50 lines of boilerplate.

#### folder.service.ts (1089 → barrel re-export)

- **D-14:** After SDK migrations (D-04, D-10), remaining functions get barrel re-exports to new module locations. The file becomes a thin re-export layer. Functions already in SDK (`loadFolder`, `createFolder`, `renameFolder`, etc.) have their web-side wrappers removed where consumers can call SDK directly.

#### bin.service.ts (962 → barrel re-export)

- **D-15:** After SDK migration of `purgeExpired()` (D-09), the deprecation header's remaining usages (`initializeBin`, `purgeExpired`) both have SDK equivalents. File can potentially be fully retired with a barrel re-export redirecting to SDK.

### Claude's Discretion

- Exact module file naming within SDK packages
- Whether to create new sub-directories in SDK or add to existing files
- Order of migration (SDK first, then web cleanup)
- Whether to update SDK package versions for the new exports

</decisions>

<canonical_refs>

## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Target Files (Web Layer)

- `apps/web/src/hooks/useSharedNavigation.ts` — 1199 lines, shared folder navigation + write ops
- `apps/web/src/components/file-browser/FileBrowser.tsx` — 964 lines, file browser with DnD + dialogs
- `apps/web/src/components/file-browser/SharedFileBrowser.tsx` — 943 lines, shared folder browser
- `apps/web/src/services/folder.service.ts` — 1089 lines, DEPRECATED per header
- `apps/web/src/services/bin.service.ts` — 962 lines, DEPRECATED per header

### SDK Packages (Migration Targets)

- `packages/sdk-core/src/` — Stateless operations (crypto, IPFS, IPNS, folder, file)
- `packages/sdk/src/client.ts` — Stateful CipherBoxClient with full API
- `packages/sdk/src/bin/index.ts` — Bin operations
- `packages/sdk/src/share/index.ts` — Share operations

### Consumer Files (Must Not Break)

- `apps/web/src/hooks/useFolderMutations.ts` — imports from folder.service (getDepth, isDescendantOf, calculateSubtreeDepth)
- `apps/web/src/hooks/useFileOperations.ts` — imports from folder.service
- `apps/web/src/components/file-browser/MoveDialog.tsx` — imports getDepth, isDescendantOf
- `apps/web/src/hooks/useBin.ts` — imports initializeBin, purgeExpired
- `apps/web/src/hooks/useAuth.ts` — imports initializeBin

### Existing Patterns

- `apps/web/src/hooks/useDialogState.ts` — Reusable dialog state hook (used by FileBrowser, target for SharedFileBrowser)
- `apps/web/src/hooks/useFolderMutations.ts` — Good example of thin hook delegating to SDK

</canonical_refs>

<code_context>

## Existing Code Insights

### Reusable Assets

- `useDialogState` hook — already battle-tested in FileBrowser, reuse for SharedFileBrowser
- `useFolderMutations` pattern — good template for how thin SDK-delegating hooks should look
- SDK's existing share module (`packages/sdk/src/share/`) — natural home for shared write context and key cache

### Established Patterns

- SDK uses `sdkCore.*` for stateless ops, `CipherBoxClient.*` for stateful
- Web hooks read Zustand stores, call SDK methods, update stores with results
- `withConflictRetry` currently in `apps/web/src/utils/folder-helpers.ts` — uses Zustand directly
- Barrel re-exports from `services/index.ts` already used

### Integration Points

- New SDK exports must be added to package `index.ts` files
- `pnpm api:generate` NOT needed (no API changes)
- `pnpm build` must pass for all SDK packages after migration
- All E2E tests must pass (sharing-workflow, writable-shares, full-workflow, recycle-bin)

</code_context>

<specifics>
## Specific Ideas

- SDK-first decomposition chosen over web-only split because business logic (tree validation, error handling, key caching, conflict retry) is framework-agnostic and benefits from being in the SDK for desktop/CLI reuse
- The existing deprecation headers on folder.service.ts and bin.service.ts already point in this direction — Phase 31 completes what 19.1 started

</specifics>

<deferred>
## Deferred Ideas

- Full retirement of folder.service.ts and bin.service.ts (remove files entirely, update all imports) — separate cleanup phase
- SDK unit tests for migrated functions — can be added alongside or in a testing phase
- Desktop app adoption of new SDK exports — future milestone
- `useFileOperations.ts` decomposition — not in scope, not in the 900+ line targets

</deferred>

---

_Phase: 31-structural-decomposition_
_Context gathered: 2026-03-28_
