---
phase: 66-api-schema-cutover-publish-gate-and-tombstone
plan: "01"
subsystem: api/ipns
tags: [entity-rename, schema-cutover, public-key-removal, tombstone-foundation]
dependency_graph:
  requires: []
  provides: [IpnsRecord-entity, tombstoned_at-column, generation-column]
  affects: [ipns-service, republish-service, vault-service, metrics-service, app-module]
tech_stack:
  added: []
  patterns: [TypeORM-entity-rename, repository-field-rename, public-key-recovery-via-name]
key_files:
  created:
    - apps/api/src/ipns/entities/ipns-record.entity.ts
  modified:
    - apps/api/src/ipns/entities/index.ts
    - apps/api/src/ipns/ipns.module.ts
    - apps/api/src/ipns/ipns.service.ts
    - apps/api/src/ipns/ipns-record.codec.ts
    - apps/api/src/republish/republish.module.ts
    - apps/api/src/republish/republish.service.ts
    - apps/api/src/vault/vault.module.ts
    - apps/api/src/vault/vault.service.ts
    - apps/api/src/metrics/metrics.module.ts
    - apps/api/src/metrics/metrics.service.ts
    - apps/api/src/app.module.ts
decisions:
  - "Prefix unused publicKey param with _ rather than removing from upsertIpnsRecord signature to preserve calling convention until 66-02 rewrites the method"
  - "Renamed public methods getFolderIpns->getIpnsRecord and getAllFolderIpns->getAllIpnsRecords to satisfy acceptance criteria substring grep; updated all spec mock stubs accordingly"
  - "publicKeyFromIpnsName is now the sole pubKey recovery path in parseCachedRecord - the cached.publicKey precedence branch was eliminated entirely"
metrics:
  duration: "~15 minutes"
  completed: "2026-06-30"
  tasks_completed: 2
  files_changed: 14
status: complete
---

# Phase 66 Plan 01: IpnsRecord Entity Rename and public_key Column Removal Summary

**One-liner:** Renamed `FolderIpns` entity to `IpnsRecord` over table `ipns_records`, dropped the `public_key` column footgun, and added `tombstoned_at` + `generation` columns; propagated the rename across all apps/api import sites so `nest build` stays green.

## Tasks Completed

| Task | Name | Commit | Key Files |
|------|------|--------|-----------|
| 1 | Create IpnsRecord entity + register in modules | 9349a1b60 | ipns-record.entity.ts, index.ts, ipns.module.ts, republish.module.ts, vault.module.ts |
| 2 | Propagate rename + remove public_key usages | f72029155 | ipns.service.ts, ipns-record.codec.ts, republish.service.ts, vault.service.ts, metrics.service.ts, metrics.module.ts, app.module.ts |

## What Was Built

### IpnsRecord Entity

- New file `apps/api/src/ipns/entities/ipns-record.entity.ts` replacing `folder-ipns.entity.ts`
- Class `IpnsRecord`, decorator `@Entity('ipns_records')`, `@Unique(['ipnsName'])` preserved
- `publicKey` column (`public_key` bytea) dropped entirely; D-03: `publicKeyFromIpnsName(ipnsName)` is the sole recovery path
- Added `tombstonedAt` column: `timestamptz`, nullable, column name `tombstoned_at`
- Added `generation` column: `bigint`, default 0, column name `generation`, TypeScript type `string` (TypeORM bigint-as-string pattern)
- All other columns carried over unchanged: `id`, `userId`, `user` relation, `ipnsName`, `latestCid`, `sequenceNumber`, `signedRecord`, `encryptedIpnsPrivateKey`, `keyEpoch`, `isRoot`, `createdAt`, `updatedAt`

### Import/Symbol Propagation

- All three modules (`ipns.module`, `republish.module`, `vault.module`) now register `IpnsRecord` in `TypeOrmModule.forFeature`
- `app.module.ts` entity list: `IpnsRecord` replaces `FolderIpns`
- Repository fields renamed throughout: `folderIpnsRepository` → `ipnsRecordRepository`
- Private method renames: `upsertFolderIpns` → `upsertIpnsRecord`, `syncFolderIpnsSequence` → `syncIpnsRecordSequence`
- Public method renames: `getFolderIpns` → `getIpnsRecord`, `getAllFolderIpns` → `getAllIpnsRecords`

### public_key Column Removal

- `ipns.service.ts`: removed `existing.publicKey` equality check, removed `existing.publicKey = ...` assignment, removed `publicKey` field from `create()` call; `_publicKey` parameter kept (prefixed) since it is still validated externally by `publishRecord` before reaching `upsertIpnsRecord`
- `ipns-record.codec.ts`: removed `cached.publicKey` precedence branch; `publicKeyFromIpnsName(cached.ipnsName)` is now the only recovery path in `parseCachedRecord`

## Verification

- `pnpm --filter @cipherbox/api build` exits 0 (nest build clean)
- `grep -rln "FolderIpns|folder-ipns.entity|folderIpnsRepository" apps/api/src --include=*.ts | grep -v '.spec.ts' | grep -v migrations` returns no matches
- `grep -c "cached.publicKey" apps/api/src/ipns/ipns-record.codec.ts` = 0
- `grep -c "existing.publicKey" apps/api/src/ipns/ipns.service.ts` = 0

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Renamed public methods and spec mock stubs to satisfy acceptance criteria**

- **Found during:** Task 2 acceptance check
- **Issue:** The plan's acceptance criteria checks for the substring "FolderIpns" across all non-spec source files. Public method names `getFolderIpns`, `getAllFolderIpns` and internal names `upsertFolderIpns`, `syncFolderIpnsSequence` all contain "FolderIpns" as a substring and would fail the grep
- **Fix:** Renamed all symbols; updated spec mock stubs and `describe()` block names accordingly to keep spec files callable
- **Files modified:** ipns.service.ts, republish.service.ts, ipns.service.spec.ts, ipns.integration.spec.ts, ipns.security.spec.ts
- **Commits:** f72029155

**2. [Rule 3 - Blocker] Built @cipherbox/crypto before nest build**

- **Found during:** Task 2 `nest build` run
- **Issue:** Worktree has fresh node_modules without built dist for workspace packages; `@cipherbox/crypto` module not found
- **Fix:** `pnpm --filter @cipherbox/crypto build` prior to `nest build`
- **Note:** pnpm install was also required first for hooks to work

## Known Stubs

None. This plan is purely mechanical entity rename and column delta; no data flows to UI.

## Self-Check

- [x] `apps/api/src/ipns/entities/ipns-record.entity.ts` exists: PASS
- [x] `apps/api/src/ipns/entities/folder-ipns.entity.ts` does NOT exist: PASS
- [x] Task 1 commit 9349a1b60 exists: PASS
- [x] Task 2 commit f72029155 exists: PASS
- [x] Build passes: PASS
- [x] No FolderIpns in non-spec non-migration source: PASS
