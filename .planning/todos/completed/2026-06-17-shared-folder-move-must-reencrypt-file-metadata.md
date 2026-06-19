---
created: 2026-06-17T00:00:00.000Z
title: Shared-folder move (when built) must re-encrypt file metadata to the destination folderKey
area: feature
severity: medium
source: decrypt-fail-after-move debug session (PR fix/decrypt-fail-after-move)
files:
  - apps/web/src/hooks/useSharedWriteOps.ts
  - apps/web/src/components/file-browser/SharedFileBrowser.tsx
  - packages/sdk/src/share/shared-write.ts
  - packages/sdk/src/client.ts
---

## Problem

Moving a file between folders within a shared folder is **not implemented today**:

- `SharedFileBrowser.tsx` renders the `ContextMenu` with `onRename`/`onDelete`
  only (gated by `isWritable`) — there is no `onMove`.
- `useSharedWriteOps` exposes `uploadFile`, `createFolder`, `renameItem`,
  `deleteItem`, `updateSharedFile` — no move operation.
- `CipherBoxClient.moveItem` operates on the owner's `folderTree`, not the
  `sharedFolderTree`.

So a write-permission recipient cannot currently move files around inside a share
(a reasonable capability they would expect).

## Why this is captured here

The `decrypt-fail-after-move` fix established that a file's `FileMetadata` IPNS
record is AES-256-GCM encrypted with its **parent folder's folderKey**. Any
operation that re-parents a file to a folder with a different `folderKey` MUST
re-encrypt the record (resolve with the source key, re-publish with the
destination key, `createVersion: false`) or every later preview/edit/download
fails with `CryptoError: Decryption failed`. This was fixed for:

- private-vault move (`CipherBoxClient.moveItem`)
- bin restore to a different folder (`restoreFromBin`, using the folderKey
  captured on the `BinEntry` at delete time)

## When implementing shared-folder move

Add a shared move (e.g. `moveInSharedFolder` in `shared-write.ts` + an SDK client
method that owns the `sharedFolderTree` publish/sequence bookkeeping, wired through
`useSharedWriteOps` and an `onMove` in the shared `ContextMenu`). It **must** apply
the same re-encrypt step when the source and destination subfolders have different
`folderKey`s — within a share, each subfolder still has its own key. Add an e2e
that asserts decrypted content survives a within-share move (mirroring
`tests/web-e2e/tests/move-restore-content.spec.ts`).
