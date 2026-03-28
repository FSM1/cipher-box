# Phase 31: Structural Decomposition - Research

**Researched:** 2026-03-28
**Status:** Complete

## Target File Analysis

### 1. useSharedNavigation.ts (1206 lines)

**Current structure:** Single hook exporting 15 return values. Contains:

- **Lines 1-136:** Types, imports, utility functions (`isForbiddenError`, `parsePublicKey`)
- **Lines 137-180:** State declarations (14 useState, 4 useRef)
- **Lines 181-280:** Share loading (`loadSharedItems`, `getShareKeys` with TTL cache)
- **Lines 281-440:** Navigation into shares (`navigateToShare` - 160 lines, handles both folder and file shares)
- **Lines 441-530:** Subfolder navigation (`navigateToSubfolder`)
- **Lines 530-700:** Back navigation, breadcrumb nav, IPNS key restoration
- **Lines 700-780:** Download, hide operations
- **Lines 780-1077:** Write operations (resync, buildSharedWriteCtx, withRevocationGuard, upload, createFolder, rename, delete, updateFile)
- **Lines 1078-1206:** Delete handler, polling effect, return value

**Natural split boundaries:**
1. Navigation state + loading + traversal (~400 lines)
2. Write operations (~300 lines)
3. Share key caching + IPNS key management (~150 lines each)

**Consumers:** Only `SharedFileBrowser.tsx` imports from this hook.

### 2. FileBrowser.tsx (965 lines)

**Current structure:** Single component with ~600 lines of handlers, ~365 lines of JSX.

- **Lines 85-115:** Hook calls (navigation, folder ops, file download, drop upload, context menu)
- **Lines 116-670:** 35+ useCallback handlers for every UI action
- **Lines 670-965:** JSX rendering

**Already uses:** `useDialogState` for some dialogs (rename, details, preview, share, edit, batch-delete, batch-move, create-folder). Well-factored dialog state management.

**Natural split:** Extract handler logic into `useFileBrowserActions` custom hook.

### 3. SharedFileBrowser.tsx (943 lines)

**Current structure:** Main component + 2 sub-components.

- **Lines 69-800:** Main `SharedFileBrowser` component
  - Lines 69-137: Hook calls and state
  - Lines 138-470: Handlers (~330 lines)
  - Lines 470-800: JSX rendering (~330 lines)
- **Lines 803-860:** `SharedListRow` sub-component
- **Lines 862-943:** `SharedFolderRow` sub-component

**Manual dialog state:** Uses individual `useState` for 6 dialogs (upload, createFolder, rename, contextMenu, sharedItemContextMenu, details). Can adopt `useDialogState`.

**Natural split:** Extract handlers into `useSharedBrowserActions` hook; extract sub-components to own files.

### 4. folder.service.ts (1083 lines)

**Current structure:** 16 exported functions, 2 private helpers.

**SDK-core already has:** `fetchAndDecryptMetadata`, `loadFolder`, `createFolder`, `renameFolder`, `deleteFolder`, `deleteFileFromFolder`, `addFileToFolder`, `addFilesToFolder`, `replaceFileInFolder`, `moveFolder`, `moveFile`, `renameFile`, `updateFolderMetadata` — most are already in `packages/sdk-core/src/folder/index.ts`.

**Still web-only:**
- `getDepth()` (line 64) — pure tree traversal
- `calculateSubtreeDepth()` (line 705) — pure tree traversal
- `isDescendantOf()` (line 733) — pure tree traversal
- `fetchAndDecryptMetadata()` (line 951) — web wrapper around SDK-core, uses web-specific `fetchFromIpfs`
- `checkAndRotateIfNeeded()` (line 1000) — TEE key rotation, complex but web-specific
- `uint8ToBase64()` (line 46) — private utility

**Consumers:** folder-helpers.ts, useFolderMutations.ts, useFileVersions.ts, useFileOperations.ts, useFolderNavigation.ts, FileBrowser.tsx, MoveDialog.tsx, services/index.ts barrel

### 5. bin.service.ts (971 lines)

**Current structure:** 9 exported functions, 3 private helpers.

**SDK already has:** `packages/sdk/src/bin/index.ts` with bin operations.

**Still web-only:** All functions in bin.service.ts are web wrappers that access Zustand stores internally. The DEPRECATED header says to use SDK methods instead.

**Consumers:** Only `useBin.ts` (initializeBin, purgeExpired) and `useAuth.ts` (initializeBin).

## Existing SDK Structure

### sdk-core (packages/sdk-core)
- `folder/index.ts` — Stateless folder CRUD (already extracted from folder.service.ts in Phase 19.1)
- `file/index.ts` — File operations
- `ipfs/index.ts`, `ipns/index.ts` — IPFS/IPNS access
- No `folder/tree.ts` exists yet (candidate for tree utilities)

### sdk (packages/sdk)
- `client.ts` — Stateful CipherBoxClient
- `bin/index.ts` — Bin operations (init, add, restore, delete, empty, purge)
- `share/index.ts` — Share key creation
- `share/shared-write.ts` — SharedWriteContext type + write operations
- `state/folder-tree.ts` — Internal folder tree state
- `state/key-cache.ts` — Key derivation cache
- No `error.ts` exists yet (candidate for error utilities)
- No `share/context.ts` exists yet (candidate for context builder)
- No `share/key-cache.ts` exists yet (candidate for share key TTL cache)

## Dependency Analysis

### Import Chain for folder.service.ts Consumers

```
MoveDialog.tsx → getDepth, isDescendantOf
useFolderMutations.ts → * as folderService (all functions)
useFileVersions.ts → * as folderService
useFileOperations.ts → * as folderService
useFolderNavigation.ts → loadFolder
FileBrowser.tsx → fetchAndDecryptMetadata
folder-helpers.ts → * as folderService
services/index.ts → re-exports all
```

Key insight: `useFolderMutations.ts` uses `import * as folderService` — barrel re-exports from the same path will preserve this pattern without any import changes.

### Import Chain for bin.service.ts Consumers

```
useBin.ts → initializeBin, purgeExpired
useAuth.ts → initializeBin
```

Only 2 consumers with named imports. These can be updated directly or barrel-redirected.

## Risk Assessment

1. **Barrel re-export correctness:** TypeScript resolves barrel re-exports identically to direct exports. No runtime risk if types match.
2. **Circular dependency risk:** Moving tree utilities to sdk-core creates no cycle (sdk-core has no web deps). Moving error utilities to sdk creates no cycle (sdk has no web deps).
3. **E2E test sensitivity:** The decomposition is purely structural — no behavior changes, no API changes, no crypto changes. E2E tests verify behavior, not file structure.
4. **Type compatibility:** All moved functions must preserve exact signatures. TypeScript compiler will catch mismatches.

## Wave Ordering Strategy

**Wave 1 (SDK-side, no web changes):**
- Create new SDK modules (tree utilities, error utilities, context builder, share key cache)
- These are pure additions — nothing breaks

**Wave 2 (Web-side barrel re-exports):**
- Redirect folder.service.ts and bin.service.ts to barrel re-exports
- Update useSharedNavigation.ts to use SDK utilities
- No consumer import changes needed (barrels preserve paths)

**Wave 3 (Component splits):**
- Split FileBrowser.tsx and SharedFileBrowser.tsx
- Extract useSharedNavigation into focused hooks
- These depend on Wave 2 SDK utilities being available

## RESEARCH COMPLETE
