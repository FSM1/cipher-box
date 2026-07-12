---
created: 2026-07-11
title: Route web listing UI through ResolvedChild.kind and revive deferred phase-62-cutover tests
area: web
files:
  - apps/web/src/components/file-browser/FileList.tsx
  - apps/web/src/components/file-browser/SharedFileBrowser.tsx
  - apps/web/src/components/file-browser/useFileBrowserActions.ts
  - apps/web/src/components/file-browser/FileBrowser.tsx
  - apps/web/src/components/file-browser/MoveDialog.tsx
  - apps/web/src/components/file-browser/SharedMoveDialog.tsx
  - apps/web/src/components/file-browser/ShareDialog.tsx
  - apps/web/src/components/file-browser/FileListItem.tsx
  - apps/web/src/components/file-browser/details/FileDetails.tsx
  - apps/web/src/components/file-browser/details/FolderDetails.tsx
  - apps/web/src/hooks/useFolderNavigation.ts
  - apps/web/src/hooks/useFolderMutations.ts
  - apps/web/src/services/invite.service.ts
  - packages/sdk-core/src/__tests__/file.test.ts
  - packages/sdk-core/src/folder/__tests__/load.test.ts
  - apps/web/src/hooks/__tests__/useSharedWriteOps.test.ts
source: TODO(phase 63/65) marker triage (2026-07-11)
resolves_phase: 79
---

## Problem

Triaging the 83 `TODO(phase 63/65)` markers left in the code from the Phase 62
node/v3 type-cutover found ~40 that are NOT stale — they describe real remaining
stub behavior in the web layer. Phase 68.2 introduced `ResolvedChild` (with a
resolved `kind`/`size`/`modifiedAt`), but the listing UI was never routed through
it: most sites still consume a bare `SealedChildRef` and hardcode `kind: 'folder'`.

Shipped consequences in the live app:

- **Folders-first sort not restored** — alphabetical only (`FileList`, `SharedFileBrowser`, `useFileBrowserActions`)
- **Drag-and-drop disabled** — drop targets + external drop (`FileList.tsx:144/145/264/268`)
- **Dialogs mislabel kind** — rename/delete/move/share always say "Folder" and stub id off `ipnsName` (`FileBrowser`, `MoveDialog`, `SharedMoveDialog`, `ShareDialog`, `FileListItem`, `useFileBrowserActions`, `invite.service`)
- **Created date stubbed** — details panes show "unavailable (phase 63)"; `createdAt` from the Node envelope isn't carried on `ResolvedChild`/`NodeContent` (`FileDetails`, `FolderDetails`)
- **Folder identity** — folder id keyed by `ipnsName` rather than `Node.id` (`useFolderNavigation.ts:321`); kind-based subtree recursion still stubbed (`useFolderMutations`)
- **Four test suites `describe.skip`'d** — `file.test.ts:186` (updateFileMetadata), `load.test.ts:44` (fetchAndDecryptMetadata D-13), `useSharedWriteOps.test.ts:428/528` (shared move/batch-move); plus the `bin.test.ts:43` fixture omits `nodeRef` though `BinEntry.nodeRef` now exists

The other 43 markers were verified stale (63/65 shipped, code migrated) and are
removed separately as a pure comment cleanup.

## Solution

See ROADMAP Phase 79 for the grouped scope and success criteria. Route every
listing/dialog/drag/sort site through `ResolvedChild.kind` (use
`isFileRefResolved`), wire `createdAt`, revive/retire the four skipped suites, and
drive the `TODO(phase 63)`/`TODO(phase 65)` marker count to zero. Relates to the
"web kind + post-upload-refresh traps" note (`isFileRef(bareSealedChildRef)` is
`false` since the 68.2-11 kind-cache removal) and 68.2 backlog item 2
(`toResolvedChildView` unresolved default).
