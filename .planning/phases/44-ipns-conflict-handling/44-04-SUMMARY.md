---
phase: 44-ipns-conflict-handling
plan: "04"
subsystem: sdk
tags:
  - conflict-handling
  - basechildren-sweep
  - lost-update-fix
  - shared-write
  - three-way-merge
dependency_graph:
  requires:
    - updateFolderMetadataAndPublish baseChildren param (44-02)
    - updateFileMetadata CAS publish new return shape (44-03)
  provides:
    - 8 client.ts callers passing baseChildren (three-way merge enabled)
    - 2 bin/index.ts callers passing baseChildren
    - 4 shared-write.ts folder callers passing baseChildren (D-08 headline fix)
    - shared-write.ts file caller consuming new Plan-03 return shape
  affects:
    - packages/sdk/src/client.ts
    - packages/sdk/src/bin/index.ts
    - packages/sdk/src/share/shared-write.ts
tech_stack:
  added: []
  patterns:
    - Pre-mutation children snapshot as baseChildren (const baseChildren = [...folder.children])
    - Three-way merge via baseChildren param adoption
    - Plan-03 CAS return shape consumption (ipnsName, metadataCid, newSequenceNumber, prunedCids)
key_files:
  created: []
  modified:
    - packages/sdk/src/client.ts
    - packages/sdk/src/bin/index.ts
    - packages/sdk/src/share/shared-write.ts
decisions:
  - "Snapshot baseChildren as a shallow copy [...folder.children] immediately before the mutation helper runs — not after, not from updatedChildren"
  - "uploadFiles uses freshFolder?.metadata.children as the snapshot base (reflecting the re-read stale-children mitigation already in that path)"
  - "shared-write.ts baseChildren is swCtx.children for all 4 sites — it is already the pre-mutation value since updatedChildren is computed from it"
  - "batchPublishIpnsRecords import retained in shared-write.ts because it is still used at line 176 for new-file IPNS record publishing during uploadToSharedFolder"
  - "Pre-existing BinEntry.type TS error in client-extended.test.ts is out-of-scope pre-existing issue — not introduced by this plan"
metrics:
  duration: "15m"
  completed: "2026-06-13"
  tasks_completed: 2
  files_created: 0
  files_modified: 3
---

# Phase 44 Plan 04: SDK Caller baseChildren Sweep Summary

14 SDK call sites wired to pass pre-mutation baseChildren snapshots so the three-way merge runs instead of the union fallback; shared-write.ts write-share paths are now the D-08 headline fix, and the file metadata call consumes Plan-03's internal-CAS return shape.

## What Was Built

### Task 1: client.ts (8 sites) + bin/index.ts (2 sites)

Each `updateFolderMetadataAndPublish` call now receives a `baseChildren` snapshot taken before the local mutation was applied:

- `createFolder` (line ~414): `const baseChildren = [...parent.children]` before `[...parent.children, folder]` spread
- `createFolder` subfolder-init (line ~432): `baseChildren: []` (new folder, always empty base)
- `renameItem` (line ~499): `const baseChildren = [...folder.children]` before `renameInFolder`
- `moveItem` dest (line ~550): `const baseDestChildren = [...dest.children]` before `moveItem`
- `moveItem` source (line ~560): `const baseSourceChildren = [...source.children]` before `moveItem`
- `deleteItem` (line ~617): `const baseChildren = [...folder.children]` before `deleteFromFolder`
- `uploadFile` (line ~726): `const baseChildren = [...folder.children]` before `addFilePointerToFolder`
- `uploadFiles` (line ~990): `const baseChildren = [...initialChildren]` where `initialChildren = freshFolder?.metadata.children ?? folder.children` (the already re-read snapshot)

`bin/index.ts`:

- `addToBin` (line ~242): `const baseChildren = [...folder.children]` before `deleteFromFolder`
- `restoreFromBin` (line ~339): `const baseChildren = [...targetFolder.children]` before the spread add

No try/catch added around any call — ConflictError propagates to callers.

### Task 2: shared-write.ts — D-08 headline fix

All 4 `updateFolderMetadataAndPublish` calls now pass `baseChildren: swCtx.children`:

- `uploadToSharedFolder` (line ~201)
- `createSharedSubfolder` (line ~296)
- `renameInSharedFolder` (line ~350)
- `deleteFromSharedFolder` (line ~377)

`swCtx.children` is the correct pre-mutation base for all four — each function computes `updatedChildren` from it directly.

**File call rewire (line ~450):** `updateFileMetadata` destructuring updated from `{ ipnsRecord }` to `await updateFileMetadata(...)` (no destructure needed — return value unused). The `batchPublishIpnsRecords([{ ...ipnsRecord, recordType: 'file' }], ...)` call that followed has been removed since `updateFileMetadata` now publishes internally via CAS (Plan 03). `prunedCids` from version overflow are still dropped here — this is the pre-existing Phase-42 deferred leak, not regressed.

## Deviations from Plan

### Build Artifact Bootstrapping

The worktree was missing built dist artifacts for `@cipherbox/sdk-core`, `@cipherbox/core`, `@cipherbox/crypto`, and `@cipherbox/api-client`. These are needed for the TypeScript compiler to resolve monorepo package types.

- **Found during:** Running `pnpm --filter @cipherbox/sdk exec tsc --noEmit`
- **Fix:** Ran `pnpm install --frozen-lockfile` then built all four packages
- **Impact:** Same pre-existing issue documented in Plans 02 and 03 summaries. Build artifacts are gitignored and not committed.

### Pre-existing BinEntry.type TypeScript Error

`packages/sdk/src/__tests__/client-extended.test.ts:658` has a pre-existing error: `BinEntry` no longer has a `type` field, but the test fixture still sets it. This error exists in HEAD and is not caused by any change in this plan (the test file has zero diff from HEAD).

- **Scope:** Out of scope per deviation rules — pre-existing, in unrelated test file, not introduced by this plan
- **Action:** Logged here; deferred to a future cleanup pass

## Known Stubs

None — no code stubs, TODO/FIXMEs, or placeholder values introduced.

## Threat Surface Scan

No new network endpoints, auth paths, file access patterns, or schema changes introduced. Changes are pure caller-side parameter additions and destructuring updates.

Threat mitigations from plan applied:

| Threat | Status |
| --- | --- |
| T-44-14: shared-write union fallback (data loss) | Mitigated — all 4 shared-write folder call sites now pass baseChildren: swCtx.children, enabling three-way merge |
| T-44-15: shared-write prunedCids drop | Not regressed — same pre-existing drop behavior; no new silent drop introduced |
| T-44-16: ConflictError swallowed | No new try/catch around any call site; ConflictError propagates to web withConflictRetry callers |

## Self-Check: PASSED

- `packages/sdk/src/client.ts` modified: confirmed on disk
- `packages/sdk/src/bin/index.ts` modified: confirmed on disk
- `packages/sdk/src/share/shared-write.ts` modified: confirmed on disk
- Task 1 commit `7058c8954` verified in git log
- Task 2 commit `bbd1fe701` verified in git log
- `grep -c "baseChildren" packages/sdk/src/client.ts` returns 13 (>= 8 required)
- `grep -c "baseChildren" packages/sdk/src/bin/index.ts` returns 4 (>= 2 required)
- `grep -c "baseChildren: swCtx.children" packages/sdk/src/share/shared-write.ts` returns 4
- `grep "ipnsRecord" packages/sdk/src/share/shared-write.ts` returns no hits (destructuring removed)
- `batchPublishIpnsRecords` at file-update site removed; only 1 active call remains at line 176 for new-file IPNS
- TypeScript: only pre-existing `client-extended.test.ts` BinEntry error remains; all 3 changed source files are clean
