---
created: 2026-07-06
title: Route SharedFolderRow drag-payload kind through the resolved listing
area: web
files:
  - apps/web/src/components/file-browser/SharedFolderRow.tsx
resolves_phase: null
---

## Problem

After the 68.2-11 kind-cache removal, `isFileRef(bareSealedChildRef)` always
returns `false`. `SharedFolderRow.tsx:111` and `:116` still call `isFileRef` on
bare `SealedChildRef`s (`selectedItems.map((i) => isFileRef(i))` and
`isFileRef(item)`) when building the drag payload `DragItem.type`, so every
shared drag item is typed `'folder'`.

**Currently harmless** (why this was deferred out of the 68.2-15 gap-closure,
not fixed): the shared drop handler `SharedFileBrowser.tsx:786` consumes only
`draggedItems.map((d) => d.id)` — it never reads `.type` — and shared moves
route by `ipnsName`, not kind. So the mis-typed value is produced but never
consumed. The owned-vault drag path (`FileListItem.tsx:95`) already classifies
correctly via `isFileRef(resolved)` on a `ResolvedChild`.

## Solution

For correctness/clarity (and to prevent a future consumer from trusting the
wrong `type`), classify these two sites against the SDK-resolved listing:

- Thread `SharedFileBrowser`'s existing `resolvedByIpnsName` map (or a
  per-item resolved lookup) into `SharedFolderRow`, and replace the two
  `isFileRef(bareRef)` calls with `isFileRefResolved(ref, resolvedByIpnsName)`
  (the helper added in 68.2-15, `apps/web/src/utils/fileTypes.ts`).

Low priority — no observable bug today; do it when SharedFolderRow next needs
touching or if a shared drag consumer starts reading `DragItem.type`.
