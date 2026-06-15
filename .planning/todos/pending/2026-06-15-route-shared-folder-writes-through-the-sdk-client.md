---
created: 2026-06-15T20:48:31.900Z
title: Route shared-folder writes through the SDK client
area: shares
severity: medium
files:
  - apps/web/src/hooks/useSharedWriteOps.ts
  - apps/web/src/hooks/useSharedNavigation.ts
  - packages/sdk/src/client.ts
  - packages/sdk/src/share/shared-write.ts
---

## Problem

Shared-folder write operations are the one remaining folder-state-mutating web
path that does NOT route through the SDK client. `useSharedWriteOps`
(apps/web/src/hooks/useSharedWriteOps.ts) calls the sdk shared-write functions
**directly**, each with a `SharedWriteContext` built from local refs
(`folderChildrenRef` / `sequenceNumberRef` in `useSharedNavigation`), never
touching `client.folderTree`:

- `uploadToSharedFolder` (line 138)
- `createSharedSubfolder` (line 189)
- `renameInSharedFolder` (line 236)
- `updateSharedFile` (line 275)
- `deleteFromSharedFolder` (line 346)

Phase 47 (PR #494) made the SDK client the single owner of **owned** folder state:
file replace, version restore/delete, folder CRUD, and bin ops now all route
through `getSdkClient().<method>()`, with the client owning publish + sequence
bookkeeping + the `folder:updated` emission. A full audit confirmed every owned
mutation is routed; shared-folder writes are the lone exception because shared
folders aren't tracked in `client.folderTree` — they have a separate key/context
model (`SharedWriteContext`). This is the same desync class the owned-folder work
eliminated (store/refs drifting from the authoritative tree, stale-sequence 409s,
edit-beats-delete resurrection), scoped to shared folders.

## Solution

Teach the SDK client to own shared-folder state, then route `useSharedWriteOps`
through it (mirrors the owned-folder consolidation):

- Decide whether shared folders join the existing `folderTree` or a sibling
  `sharedFolderTree` keyed by share — they carry a distinct key/context
  (`SharedWriteContext`), so a parallel structure is likely cleaner.
- Add client methods (e.g. `uploadToSharedFolder` / `createSharedSubfolder` /
  `renameInSharedFolder` / `updateSharedFile` / `deleteFromSharedFolder`) that own
  the publish + sequence bookkeeping + a `folder:updated`-style emission internally.
- Make `useSharedNavigation`'s `folderChildrenRef` / `sequenceNumberRef` a
  projection fed by those events — never written from the write hook directly.

**Scope:** medium, multi-PR. Not a correctness blocker today (shared folders are a
self-contained state model, so there is no cross-contamination with the owner's
`folderTree`), but it leaves shared folders outside the single-ownership invariant
and re-exposes the desync footgun for any new shared-write path.

**References:** PR https://github.com/FSM1/cipher-box/pull/494 (owned-folder
consolidation + the audit that surfaced this gap). Related but distinct todos:
`2026-06-14-unify-folder-state-ownership-in-sdk-client.md` (owned-folder
counterpart, largely delivered by PR #494) and
`2026-06-14-updatesharedfile-discards-prunedcids-from-updatefilemetadata.md`
(shared-file pin-leak in the same sdk share-write module).
