---
created: 2026-06-16T00:00:00.000Z
title: SDK client self-bootstrap folder tree from root IPNS key
area: architecture
severity: medium
files:
  - packages/sdk/src/types.ts:44
  - packages/sdk/src/client.ts:288
  - packages/sdk/src/client.ts:345
  - packages/sdk/src/bin/index.ts:323
  - apps/web/src/hooks/useBin.ts:73
  - apps/web/src/hooks/useBin.ts:128
  - apps/web/src/lib/sdk-provider.ts:96
---

## Problem

`CipherBoxClient` is positioned as the stateful owner of all folder operations
(holds `folderTree`, `binState`, `keyCache`, `vaultKeypair`, `rootFolderKey`),
but `CipherBoxClientConfig` (`packages/sdk/src/types.ts:44`) carries
`rootIpnsName` + `rootFolderKey` + `vaultKeypair` and **NOT** the root IPNS
private key. The root IPNS keypair lives only in the web `vaultStore`. So the
client cannot resolve/publish root or lazy-load folders from root on its own —
the web app must seed `folderTree` via `ensureFolderRegistered`
(`apps/web/src/lib/sdk-provider.ts:96`) before every folderTree-dependent client
method (`replaceFile`, `restoreFileVersion`, `deleteFileVersion`,
`restoreFromBin`, `renameItem`, `deleteItem`, `uploadFile(s)`, `moveItem`,
`createFolder`, `shareFolder`).

This asymmetry is the root cause of the whole "Folder not loaded" bug class.
Every folderTree-dependent method throws `'Folder not loaded'` (or
`'Target folder not loaded'`) when the web forgot to seed it. The PR #494
regression was simply three of those seeding calls being dropped (fixed on branch
`fix/owner-edit-folder-not-loaded` by adding `ensureFolderRegistered` to
`useFileOperations` + `useFileVersions`).

### Concrete still-open instance: bin restore

Restoring a recycle-bin item after a client re-creation (page reload / re-login)
throws `'Target folder not loaded'` when the item's original parent folder was
never navigated to that session. Throw site: `packages/sdk/src/bin/index.ts:323`
(`restoreFromBin` derefs `folderTree.get(targetFolderIpnsName)` to get the parent
key + ipnsKeypair needed to republish the parent). Web callers
`apps/web/src/hooks/useBin.ts:73` (`restore`) and `:128` (`restoreMultiple`)
never register the target folder. **Pre-existing since PR #296**, not a #494
regression. Not caught by `tests/web-e2e/tests/recycle-bin.spec.ts` because that
test navigates/uploads first (parent already in `folderTree`) and never reloads.

A localized guard isn't enough here: bin entries carry only
`originalParentIpnsName`, and after a reload the parent may not be in the Zustand
store at all, so there is nothing to register. The parent's keys live in *its*
parent's `FolderEntry`, so loading it by ipnsName requires walking from root.

## Solution

Make the stateful client able to bootstrap and lazy-load on its own, dissolving
the `ensureFolderRegistered` workaround class:

1. Add `rootIpnsKeypair` (root IPNS private key) to `CipherBoxClientConfig`. The
   web passes it from `vaultStore` at `initSdkClient`. Security: no new exposure —
   the client already holds `vaultKeypair.privateKey`, `rootFolderKey`, and every
   loaded folder's `ipnsPrivateKey` in memory (zeroed on `destroy()`); the root
   ipns private key is consistent with that.
2. Have the client self-register root (resolve + register) on init or lazily.
3. Implement an internal `ensureFolderLoaded(targetIpnsName)` that DFS-walks the
   folder tree from root, unwrapping each `FolderEntry`'s keys with the vault
   keypair and loading metadata (`loadFolder`/`loadFolderMetadata`) until the
   target is registered.
4. Call `ensureFolderLoaded` inside the folderTree-dependent methods — definitely
   `restoreFromBin`, and as a safety net for `replaceFile` / `restoreFileVersion`
   / `deleteFileVersion` / `renameItem` / `deleteItem` / `uploadFile(s)` /
   `moveItem`. Then the web-side `ensureFolderRegistered` calls can be removed.

### Tests

- SDK unit test for `ensureFolderLoaded`: deep target, target-not-found,
  already-loaded (no-op).
- New web E2E: reload → open bin → restore an item whose subfolder parent was
  never navigated to (the scenario `recycle-bin.spec.ts` misses).

### Related

- `[[route-shared-folder-writes-through-the-sdk-client]]` — adjacent SDK-client
  ownership cleanup (shared-write paths). Both move state authority into the SDK.
- The #494 hotfix (`fix/owner-edit-folder-not-loaded`) is the symptom patch this
  todo would supersede.
