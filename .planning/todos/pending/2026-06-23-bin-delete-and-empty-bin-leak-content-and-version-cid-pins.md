---
created: 2026-06-23T20:26:04.678Z
title: Bin delete and empty-bin leak content and version CID pins
area: infra
severity: high
source: Staging investigation 2026-06-23 — user with empty vault+bin shows 442 MB quota used
files:
  - packages/sdk/src/bin/index.ts
  - packages/core/src/bin/types.ts
  - packages/core/src/file/types.ts
  - packages/sdk-core/src/folder/registration.ts
  - apps/api/src/vault/vault.service.ts
  - apps/api/src/vault/entities/pinned-cid.entity.ts
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

1. `addToBin` must resolve and store the file's `contentCid` (`FileMetadata.cid`) and `versionCids`
   (`FileMetadata.versions[].cid`) into the `BinEntry` at delete time.
2. `emptyBin` / `permanentDeleteFromBin` / `purgeExpiredEntries` must unpin `contentCid` AND every
   `versionCid` (not just the guarded `contentCid`).
3. Consider unpinning the superseded metadata CID on CAS publish to stop metadata-blob accumulation.
4. Add an SDK or E2E test that asserts quota drops after empty-bin (upload, delete-to-bin, empty,
   re-read quota → released).
5. Optional one-off staging remediation: reclaim this user's 442 MB by deleting the orphaned
   `pinned_cids` rows + Kubo unpin, after confirming the 9 big CIDs are unreachable from the user's
   current IPNS metadata (needs client keys, so the user must confirm the files are truly gone).

Related (distinct): `2026-06-22-periodic-kubo-ipfs-gc-on-staging.md` covers *unpinned* blocks not being
garbage-collected (server/infra). This todo is the upstream cause for one class of that garbage —
pins that should have been released but never were. GC alone cannot reclaim these because they are
still pinned.
