---
created: 2026-06-14T18:49:51.903Z
title: Unify folder-state ownership in the SDK client
area: sdk
severity: medium
files:
  - packages/sdk/src/client.ts
  - apps/web/src/lib/sdk-provider.ts
  - apps/web/src/hooks/useFileOperations.ts
  - apps/web/src/hooks/useFileVersions.ts
  - apps/web/src/stores/folder.store.ts
---

## Problem

Folder state (children + IPNS `sequenceNumber`) is duplicated across two stores
that can silently drift:

1. Web Zustand `useFolderStore` (apps/web) — drives the UI.
2. SDK client `folderTree` (packages/sdk `client.ts`) — used by SDK-routed
   mutations (`deleteToBin`, `move`, `rename`, folder create) and by the headless
   desktop FUSE mount.

`ensureFolderRegistered` (apps/web/src/lib/sdk-provider.ts) treats the `folderTree`
as authoritative and historically **no-opped once a folder was registered**. But
some web paths publish folder metadata **directly via sdk-core**
(`updateFolderMetadataAndPublish` / `replaceFileInFolder`) and update only the
Zustand store, bumping its IPNS `sequenceNumber` + child `modifiedAt`. The SDK
`folderTree` is never told → it goes stale.

This was the root cause of PR #489's **deterministic** web-e2e failure
(recycle-bin TC08): after a file replace, a soft-delete via the stale `folderTree`
published at a stale sequence → 409 → the 409 merge's edit-beats-delete branch saw
`remote.modifiedAt > staleBase.modifiedAt` and **resurrected the just-deleted
file**. PR #489 shipped a reconciliation patch (`client.reconcileFolderState` +
`ensureFolderRegistered` calling it) — a band-aid that papers over the desync at
the SDK-mutation boundary, not a cure. A residual sub-second race remains (delete
firing between a replace's publish landing and its fire-and-forget `.then`
updating the store sequence), and any new direct-publish path can reintroduce the
bug.

**Bypass-path inventory (the leak):**

- `useFileOperations.updateFile` (file replace) — the fire-and-forget "6b" folder
  republish.
- `useFileVersions.handleRestoreVersion` and `handleDeleteVersion` (+ lazy
  IPNS-key migration).

These call sdk-core publish helpers directly and update only the Zustand store.

## Solution

Make the **SDK client the single source of truth** for folder children +
`sequenceNumber`. The SDK is also consumed headless (desktop FUSE uses `client`
with no Zustand), so the SDK — not the store — must own state; making the SDK
stateless is ruled out.

- Convert the bypass paths into client methods (e.g. `client.replaceFile()` /
  `client.updateFileMetadata()`) that own publish + sequence bookkeeping +
  `folder:updated` emission internally.
- Make the web `useFolderStore` a **projection**: keep UI/navigation state
  (`isLoaded`, `currentFolderId`, `breadcrumbs`, `parentId` tree) and a render
  copy of children, but write `children`/`sequenceNumber` **only** via
  `folder:updated` events — never from web mutation code.
- Aligns with the existing "gradual SDK adoption" bridge comment on
  `client.registerFolder`.

**Exit criteria:** delete `client.reconcileFolderState` (becomes dead code — the
desync is impossible by construction), which also closes the residual race.

**Scope:** medium, multi-PR refactor. Do NOT fold into the PR #489 bugfix.

**References:** PR https://github.com/FSM1/cipher-box/pull/489; harness memory
`project-web-sdk-folder-state-desync`. Related but distinct todo:
`2026-06-14-unify-file-and-folder-ipns-cas-retry-into-one-publishwithcas.md`
(that one dedups the CAS *retry-loop code* in sdk-core; this one fixes folder
*state ownership* across the web/SDK boundary).
