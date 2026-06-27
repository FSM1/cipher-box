---
created: 2026-06-23T20:26:04.678Z
title: Bin delete and empty-bin leak content and version CID pins
area: infra
severity: high
source: Staging investigation 2026-06-23 — user with empty vault+bin shows 442 MB quota used
files:
  - packages/sdk/src/bin/index.ts
  - packages/sdk/src/share/index.ts
  - packages/sdk/src/client.ts
  - packages/core/src/bin/types.ts
  - apps/api/src/shares/shares.service.ts
  - apps/api/src/shares/shares.controller.ts
  - apps/api/src/shares/dto/revoke-for-items.dto.ts
resolves_phase: 65
---

## Problem

A staging user whose vault AND bin both appear empty shows ~442 MB of quota used. This is a real
storage/cost-correctness bug, not a display glitch — the quota number is correct; the bytes are
genuinely still pinned and never released on delete.

### Evidence (staging Postgres, user 0e2a64cd-6bd0-494c-88fc-2f9eb1364c6d)

Pubkey `046d97e4bdb4e5f98f86bc9ff0367e1e427e18a28fba558827b01b8133cacdd55f769aebb29e4941e5e70fd0d1303941af252f0411e7c45cabfd2f10697fe02a1b`.

- `pinned_cids` holds 239 rows / 442 MB for this user.
- 9 CIDs of 1 MB or larger account for 439 MB, all pinned 2026-03-30 to 2026-04-02 and never re-touched.
- `pending_unpins` = 0 rows — an unpin was never even requested.
- Account is actively used: 32 `folder_ipns` rows, root at sequence 70, last publish today. The other
  ~230 pins are tiny (under 10 KB) superseded metadata blobs.

### Root cause (client-side SDK, NOT server accounting)

Server quota = live `SUM(pinned_cids.size_bytes)` per user; the only decrement path is
`POST /ipfs/unpin` to `VaultService.guardedUnpin` (`apps/api/src/vault/vault.service.ts`,
`getQuota`/`recordPin`/`guardedUnpin`). The server has no files/file_versions table — file structure
lives entirely in client-encrypted IPNS metadata, so the server cannot tell which pinned CIDs are
still referenced. The client never asks to unpin on delete:

- `addToBin` (`packages/sdk/src/bin/index.ts`, around L241/L290) builds the `BinEntry` but never
  populates `contentCid` / `versionCids` (optional fields in `packages/core/src/bin/types.ts:37-41`).
  The real content CID lives in the file's own IPNS record (`FileMetadata.cid` via
  `FilePointer.fileMetaIpnsName`, `packages/core/src/file/types.ts:34`), which `addToBin` never resolves.
- Therefore `emptyBin` (~L557), `permanentDeleteFromBin` (~L514) and `purgeExpiredEntries` (~L599) all
  gate their unpin on `if (entry.contentCid)` — always `undefined` → the unpin never fires. Emptying
  the bin clears the bin metadata but releases zero bytes.
- Secondary leak: CAS metadata publish (`packages/sdk-core/src/folder/registration.ts`
  `updateFolderMetadataAndPublish` to `addToIpfs` to `recordPin`) uploads a fresh pinned metadata blob
  on every publish and never unpins the superseded one (the under-10 KB pin tail).
- Version retention (VER-01) is intentional, but deleting a versioned file to bin then emptying it
  leaks every `FileMetadata.versions[].cid` too.

Net: every user who deletes files leaks the content CID, all version CIDs, and stale metadata blobs
forever, while their vault/bin look empty.

## Solution

Shipped as ONE PR (`fix(bin): unpin deleted content and revoke its shares`). Items 1, 2 and 4
implemented; the share-revocation safety net was added because once empty-bin actually unpins, an
unpin of a still-shared content CID would orphan the sharee (sharees never get their own
`pinned_cids` row, so the only thing protecting shared content today is the unpin never firing).
Items 3 and 5 are deferred to separate follow-up todos.

### Implemented

1. CID capture at delete time (`addToBin`, `packages/sdk/src/bin/index.ts`):
   - File delete: resolve the file's own `FileMetadata` (via `FilePointer.fileMetaIpnsName`, decrypt
     with the parent `folderKey`) and store `contentCid` + `contentSize` + `versionCids` on the
     `BinEntry`.
   - Folder delete: recursively walk the WHOLE deleted subtree (resolve+decrypt each folder, unwrap
     each subfolder's `folderKey`, capture every descendant file's content + version CIDs) and store
     the flattened list in the new `BinEntry.descendantCids` (`packages/core/src/bin/types.ts`).
     RecycleBinMetadata stays `v1` — the new field is additive/optional.
   - The walk is FAIL-CLOSED on structure: if a descendant folder's metadata won't resolve, the whole
     delete aborts (the share set can't be guaranteed complete). Per-file CID capture inside a
     successful walk is best-effort (log + skip the CID; the file's ipnsName is still revoked).
2. Unified unpin: one shared `unpinEntryCids(ctx, entry)` helper unpins `contentCid` + every
   `versionCids[].cid` + every `descendantCids[].cid`, each in its own try/catch. Called from
   `emptyBin`, `permanentDeleteFromBin` AND `purgeExpiredEntries` (this also fixes the prior bug where
   the first two never looped `versionCids`).
3. Share revocation at delete time (the safety net): a NEW atomic bulk endpoint
   `POST /shares/revoke-for-items` (`apps/api/src/shares`, body `{ ipnsNames: string[] }`) HARD-deletes
   all `Share` rows (CASCADE drops `ShareKey`) and marks active `ShareInvite` rows `revoked`, for the
   authed sharer, `WHERE ipnsName IN (list)` — in one transaction. The client collects EVERY node
   ipnsName in the deleted subtree (folder's own + every descendant file `fileMetaIpnsName` + every
   descendant subfolder ipnsName; single-file delete = `[fileMetaIpnsName]`) and `addToBin` calls the
   endpoint (with a couple of retries) BEFORE the destructive folder mutation. Ordering is fail-closed:
   walk → revoke → folder mutate + publish → build bin entry → publish bin. Revoke is ONE-WAY (restore
   does NOT resurrect shares — owner re-shares manually).
4. Tests: SDK unit tests (file delete captures content + version CIDs and revokes its ipnsName before
   the folder publish; folder delete walks the subtree, stores `descendantCids`, revokes all node
   ipnsNames, and is fail-closed when a subtree folder won't enumerate; emptyBin / permanentDelete
   unpin content + versions + descendants). API service + controller specs for the new endpoint.

### Deferred (separate follow-up todos)

- (was item 3) CAS superseded-metadata-blob unpin on every publish — the under-10 KB pin tail.
- (was item 5) One-off staging remediation of the existing 442 MB (`pinned_cids` cleanup + Kubo unpin)
  for the affected user, after confirming the big CIDs are unreachable from current IPNS metadata.

Related (distinct): `2026-06-22-periodic-kubo-ipfs-gc-on-staging.md` covers *unpinned* blocks not being
garbage-collected (server/infra). This todo is the upstream cause for one class of that garbage —
pins that should have been released but never were. GC alone cannot reclaim these because they are
still pinned.
