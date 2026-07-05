---
created: 2026-07-04T00:00:00Z
title: Owner sees stale/empty contents of a shared-out folder until they write to it (no per-navigation re-resolve)
area: web
files:
  - apps/web/src/hooks/useFolderNavigation.ts:167
  - apps/web/src/hooks/useFolderMutations.ts:137
  - apps/web/src/components/file-browser/useFileBrowserActions.ts:109
  - apps/web/src/hooks/folder-helpers.ts:15
  - packages/sdk/src/client.ts:949
source: Phase 68.1 local smoke test (user-reported, root-caused, deferred)
---

## Problem

Owner A creates an empty folder, shares it Read+Write with B. B uploads a file
into it (publishing a correct higher-sequence IPNS record with the file sealed
into A's read plane). A navigates into the folder in their OWN vault and sees
nothing — the file only appears after A themselves writes into the folder, or a
hard reload.

The writer side is correct (verified): `uploadToSharedFolder` seals the new
`SealedChildRef` into the parent read-body under the shared folderKey and
publishes to the shared folder's own ipnsName at `sequence+1`
(`packages/sdk/src/share/shared-write.ts:508-528`, `247-286`). This is purely an
owner-side refresh/staleness defect. Not data loss, not a security hole.

Root cause — the owner never re-resolves a shared-out folder's IPNS after the
initial seed:

1. At create time the store node is seeded `isLoaded: true, children: []`
   (`useFolderMutations.ts:137-149`).
2. `navigateTo` fast-paths on `isLoaded` and returns without resolving IPNS
   (`useFolderNavigation.ts:167-193`, esp. `:189`); the SDK's
   `ensureFolderLoaded` likewise returns the cached `folderTree` FolderState
   with no resolve (`client.ts:949-958`).
3. The 30s sync poll only re-resolves ROOT and updates `'root'`
   (`useFileBrowserActions.ts:109-155`); it early-returns at the
   `resolved.sequenceNumber <= rootFolder.sequenceNumber` guard because root's
   ipnsName-keyed child-ref to the shared folder is unchanged, so it never
   descends into the subfolder. Polling can never pick up a grantee's write into
   an owned subfolder.
4. `resyncFolder` (`folder-helpers.ts:15-36`) is the only on-demand per-folder
   re-resolve helper and is currently dead code (zero call sites).

Refresh matrix for an owned, shared-out folder:

| Trigger | Re-resolves the folder's IPNS? |
|---|---|
| Navigate into it (same session, `isLoaded:true`) | No — cached |
| 30s sync poll | No — root-only |
| Owner mutates inside it | Yes (SDK write path resolves fresh) |
| Hard reload | Yes — cold DFS via `ensureFolderLoaded` |
| `resyncFolder` | N/A — never called |

## Solution

Force a fresh IPNS resolve when navigating into (or polling) a folder the owner
shared out with write access — i.e. a folder that a grantee can mutate out from
under the owner's cache. Options:

- Wire `resyncFolder` into `navigateTo` for folders flagged as shared-out
  (or drop/ignore `isLoaded` for such folders so the `!isLoaded` branch runs
  `ensureFolderLoaded`), and add a matching cache-bypass in
  `ensureFolderLoaded`/`folderTree` for that folder.
- Or extend the sync poll to also re-resolve the ipnsNames of owned folders that
  have outstanding write-grants, not just root.

Mind `folder.store.ts:227-237` (the guard that refuses to blank a loaded folder
on an empty incoming event) — that guards inbound events, not the missing
re-resolve, but a naive "clear children then reload" could trip it.

MUST add a writable-shares web-e2e: A shares Read+Write, B uploads into the
folder, A navigates in (without writing) and asserts B's file is visible. Relates
to [[shared-nav-stack-stale-children-snapshot]],
[[nested-shared-write-key-lost-on-up-breadcrumb-restore]], and
[[web-sdk-folder-state-desync]].
