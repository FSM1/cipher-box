# Phase 38: Retire deprecated web services - Research

**Researched:** 2026-03-31
**Status:** Complete

## Research Question

What do I need to know to PLAN the retirement of `folder.service.ts` and `bin.service.ts` and the removal of the `@cipherbox/crypto` -> `@cipherbox/core` circular devDependency?

## 1. Deprecated Services Inventory

### folder.service.ts (1,059 LOC)

**Functions still called by web app code:**

| Function                                  | Callers                                         | SDK Equivalent                                                                                       |
| ----------------------------------------- | ----------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `fetchAndDecryptMetadata(cid, folderKey)` | `folder-helpers.ts`, `useFileBrowserActions.ts` | `fetchAndDecryptMetadata(cid, folderKey, ctx)` in `@cipherbox/sdk-core`                              |
| `loadFolder(...)`                         | `useFolderNavigation.ts`                        | `loadFolderMetadata(params)` in `@cipherbox/sdk-core` (returns metadata, not FolderNode)             |
| `addFileToFolder(params)`                 | `useFileOperations.ts`                          | No direct SDK equivalent — uses `CipherBoxClient.uploadFile()` which handles registration internally |
| `addFilesToFolder(params)`                | `useFileOperations.ts`                          | No direct SDK equivalent — uses `CipherBoxClient.uploadFiles()`                                      |
| `replaceFileInFolder(params)`             | `useFileOperations.ts`, `useFileVersions.ts`    | No direct SDK equivalent — file metadata publish is internal to SDK                                  |
| `getDepth(folderId, folders)`             | `folder-helpers.ts`, `useFolderMutations.ts`    | `getDepth` in `@cipherbox/sdk-core` (re-exported from tree.ts)                                       |
| `isDescendantOf(...)`                     | `useFolderMutations.ts`, `MoveDialog.tsx`       | `isDescendantOf` in `@cipherbox/sdk-core`                                                            |
| `calculateSubtreeDepth(...)`              | `useFolderMutations.ts`                         | `calculateSubtreeDepth` in `@cipherbox/sdk-core`                                                     |

**Functions already delegating to SDK (thin wrappers):**

- `getDepth` -> `sdkGetDepth` from `@cipherbox/sdk-core`
- `calculateSubtreeDepth` -> `sdkCalculateSubtreeDepth` from `@cipherbox/sdk-core`
- `isDescendantOf` -> `sdkIsDescendantOf` from `@cipherbox/sdk-core`

**Functions NOT called (dead code after prior migrations):**

- `createFolder` — SDK `CipherBoxClient.createFolder()` used
- `updateFolderMetadata` — SDK handles
- `renameFolder` — SDK `CipherBoxClient.renameItem()` used
- `deleteFolder` — SDK `CipherBoxClient.deleteItem()` used
- `deleteFileFromFolder` — SDK handles
- `moveFolder` — SDK `CipherBoxClient.moveItem()` used
- `moveFile` — SDK `CipherBoxClient.moveItem()` used
- `renameFile` — SDK `CipherBoxClient.renameItem()` used
- `checkAndRotateIfNeeded` — SDK handles rotation

### bin.service.ts (971 LOC)

**Functions still called by web app code:**

| Function                | Callers                   | SDK Equivalent                                                      |
| ----------------------- | ------------------------- | ------------------------------------------------------------------- |
| `initializeBin(params)` | `useAuth.ts`, `useBin.ts` | `CipherBoxClient.loadBin()`                                         |
| `purgeExpired(params)`  | `useBin.ts`               | No direct public SDK method — but SDK bin module has internal logic |

**Functions NOT called (dead code):**

- `addToBin` — SDK `CipherBoxClient.deleteToBin()` used
- `addManyToBin` — SDK handles batch via SDK
- `restoreFromBin` — SDK `CipherBoxClient.restoreFromBin()` used
- `restoreFromBinBatch` — SDK handles
- `permanentlyDelete` — SDK `CipherBoxClient.permanentDelete()` used
- `permanentlyDeleteBatch` — SDK handles
- `emptyBin` — SDK `CipherBoxClient.emptyBin()` used

## 2. Migration Analysis

### Category A: Direct SDK-core import replacements (trivial)

Functions that are already thin wrappers around SDK-core exports. Callers just need to change the import path.

- `getDepth` -> import from `@cipherbox/sdk-core`
- `calculateSubtreeDepth` -> import from `@cipherbox/sdk-core`
- `isDescendantOf` -> import from `@cipherbox/sdk-core`

### Category B: SDK-core function with different signature

- `fetchAndDecryptMetadata(cid, folderKey)` in folder.service uses web app's `fetchFromIpfs` (from `lib/api/ipfs`), while SDK-core version takes `SdkContext` as third param. Callers need to get `SdkContext` from the SDK client.
  - **Option 1:** Use `getSdkClient()` to get context and call SDK-core's version
  - **Option 2:** Inline the logic (fetch from IPFS, parse JSON, decrypt) — but this duplicates SDK-core
  - **Chosen approach:** Use SDK client's internal context. The `CipherBoxClient` has `getContext()` or callers can use `getSdkClient()` pattern.

- `loadFolder(...)` returns a `FolderNode` (web-specific type) while SDK-core's `loadFolderMetadata` returns `{metadata, sequenceNumber, cid}`. The caller (`useFolderNavigation`) constructs the `FolderNode` from the result. The migration needs to: (1) call SDK-core's `loadFolderMetadata` or SDK-core's `fetchAndDecryptMetadata`, and (2) construct the `FolderNode` in the hook.

### Category C: Operations that need new SDK-level exports or inlining

- `addFileToFolder` / `addFilesToFolder` / `replaceFileInFolder` — These are called from `useFileOperations` and `useFileVersions`. These hooks manage the "register file in folder after upload" flow which is separate from `CipherBoxClient.uploadFile()` (that method does the full upload + register in one call).

  Looking at the callers more closely:
  - `useFileOperations.handleAddFile` creates file metadata IPNS record first, then calls `addFileToFolder` to register in folder — this is the legacy per-file-IPNS registration flow
  - The SDK's `uploadFile` does this internally as part of the upload pipeline
  - **Key question:** Are these hooks still used, or have callers migrated to the SDK upload path?

  Checking further: `useFileOperations` is imported by the file browser's drag-drop upload and the upload dialog. The SDK `CipherBoxClient.uploadFile()` is the modern path. The legacy `handleAddFile` in useFileOperations may still be needed for the upload dialog's flow where file encryption happens in a Web Worker, then registration is a separate step.

  **Approach:** These functions need to be extracted to SDK-core or inlined in the hooks. Since they use `batchPublishIpnsRecords` (from ipns.service), they need the IPNS publishing capability. The simplest path is to move `addFileToFolder`, `addFilesToFolder`, and `replaceFileInFolder` to `@cipherbox/sdk-core` folder module.

### Category D: Bin operations needing SDK client migration

- `initializeBin` — Reads from/writes to `useBinStore`. The SDK's `CipherBoxClient.loadBin()` does the same thing but updates SDK internal state. The web hook then needs to bridge SDK state to Zustand store.
  - **Current flow:** `initializeBin` -> load bin from IPNS -> update `useBinStore`
  - **SDK flow:** `getSdkClient().loadBin()` -> returns `BinState` -> hook updates `useBinStore`
  - The `useBin.loadBin` already does `getSdkClient().loadBin()` after `initializeBin` as a second step. The migration simplifies to just using the SDK client.

- `purgeExpired` — Filters expired entries, cleans up CIDs, removes from bin. The SDK doesn't expose a public purge method, but the logic is self-contained: filter entries by retention, cleanup CIDs, save updated bin.
  - **Approach:** Add a `purgeExpired` method to `CipherBoxClient` or move the purge logic into the `@cipherbox/sdk` bin module as a public function. Since the SDK bin module already has all the internals (loadBinMetadata, saveBinMetadata, cleanup), adding purgeExpired there is straightforward.

## 3. Circular Dependency Fix

### Current state

- `packages/crypto/package.json` has `@cipherbox/core` as a devDependency
- `packages/crypto/src/__tests__/vault-ipns.test.ts` imports `deriveRegistryIpnsKeypair` and `initializeVault` from `@cipherbox/core`
- This creates a circular dependency: `crypto` -> `core` (dev) and `core` -> `crypto` (prod)

### What the test verifies

1. `deriveVaultIpnsKeypair` determinism
2. Different keys produce different results
3. **Domain separation:** vault IPNS name !== registry IPNS name for same key (this is the import that needs `@cipherbox/core`)
4. Invalid key size handling
5. IPNS name format (k51 prefix)
6. `initializeVault` deterministic IPNS keypair (uses `@cipherbox/core`)
7. `initializeVault` random rootFolderKey
8. `initializeVault` rootIpnsKeypair matches `deriveVaultIpnsKeypair`

### Fix approach (per D-04)

Replace `deriveRegistryIpnsKeypair` and `initializeVault` imports with hardcoded test vectors:

1. Run `deriveRegistryIpnsKeypair` with a known private key, capture the output (ipnsName, publicKey, privateKey)
2. Run `initializeVault` with a known private key, capture the deterministic output (rootIpnsKeypair)
3. Embed these as hex constants in the test file
4. Test domain separation by comparing `deriveVaultIpnsKeypair(knownKey).ipnsName !== HARDCODED_REGISTRY_IPNS_NAME`
5. Test `initializeVault` by comparing `deriveVaultIpnsKeypair(knownKey)` against `HARDCODED_VAULT_IPNS_KEYPAIR`
6. Remove `@cipherbox/core` from crypto's devDependencies

## 4. services/index.ts Barrel File

Currently exports:

```typescript
export * from './delete.service';
export * from './download.service';
export * from './file-crypto.service';
export * from './file-metadata.service';
export * from './streaming-crypto.service';
export * from './folder.service';
export * from './ipns.service';
export * from './upload.service';
export { searchIndexService, type SearchResult } from './search-index.service';
```

Need to remove: `export * from './folder.service'`
Note: `bin.service.ts` is NOT in the barrel file (it's imported directly by callers).

## 5. Risk Assessment

### Low risk

- Tree utility imports (getDepth, isDescendantOf, calculateSubtreeDepth) — pure function re-imports
- Barrel file cleanup — straightforward removal
- Circular dependency fix — isolated test file change

### Medium risk

- `loadFolder` migration — needs careful FolderNode construction in hook
- `fetchAndDecryptMetadata` — needs SdkContext bridge
- `initializeBin` / `purgeExpired` — store bridging changes

### Higher risk

- `addFileToFolder` / `addFilesToFolder` / `replaceFileInFolder` — These are in the critical upload path. Need to verify whether they're still called or if the SDK upload pipeline has replaced them entirely.

## 6. Validation Architecture

### Approach: Compilation + functional verification

1. **Type check:** `pnpm typecheck` must pass with no errors after all migrations
2. **No dead imports:** `grep -r "folder.service\|bin.service" apps/web/src/` returns zero results
3. **Files deleted:** `folder.service.ts` and `bin.service.ts` no longer exist
4. **Circular dependency:** `@cipherbox/core` not in crypto's package.json
5. **Tests pass:** `pnpm --filter @cipherbox/crypto test` passes
6. **Build succeeds:** `pnpm build` for affected packages succeeds

---

_Phase: 38-retire-deprecated-web-services_
_Research completed: 2026-03-31_
