---
phase: 47-sdk-folder-state-publish-consolidation
plan: "03"
subsystem: sdk
tags: [sdk, client, folder-state, file-ops, tdd]
dependency_graph:
  requires: [publishWithCas]
  provides:
    - CipherBoxClient.replaceFile
    - CipherBoxClient.restoreFileVersion
    - CipherBoxClient.deleteFileVersion
    - REQ-1-client-single-source-of-truth
  affects:
    - packages/sdk/src/client.ts
tech_stack:
  added: []
  patterns: [canonical-5-step-publish, folder-updated-emission, folderTree-as-source-of-truth, tdd-red-green]
key_files:
  created:
    - packages/sdk/src/__tests__/client-file-ops.test.ts
  modified:
    - packages/sdk/src/client.ts
decisions:
  - "Three new methods (replaceFile, restoreFileVersion, deleteFileVersion) own publish + folderTree sequence bookkeeping + folder:updated emission internally, reading authoritative state from folderTree.get() at call time (REQ-1, D-1)"
  - "Methods accept PRE-RESOLVED fileIpnsPrivateKey + currentMetadata; restore/delete service logic stays in the web tier (locked decision 2)"
  - "Methods do NOT zero fileIpnsPrivateKey — updateFileMetadata owns zeroing in its own finally; caller owns any additional lifecycle (T-47-01)"
  - "replaceFile returns prunedCids for caller-side unpin; deleteFileVersion returns deletedCid"
  - "reconcileFolderState DELETED from client.ts — dead by construction once the web bypass paths route through these methods (REQ-1 exit criterion)"
  - "restore/delete folder publish is CONDITIONAL on key-epoch migration; otherwise the file-only publish does not advance the folder sequence, and folder:updated emits the read-back folderTree snapshot for a consistent event in both branches"
metrics:
  duration: "backfilled"
  completed_date: "2026-06-15"
  tasks_completed: 2
  files_changed: 2
status: complete (backfilled 2026-06-17 — plan shipped via PR #494, summary reconstructed retroactively)
---

# Phase 47 Plan 03: SDK client file-ops methods Summary

One-liner: Added `replaceFile`, `restoreFileVersion`, and `deleteFileVersion` to `CipherBoxClient` so the SDK client owns the publish + folderTree bookkeeping + `folder:updated` emission cycle, and deleted the `reconcileFolderState` band-aid.

## What Was Built

### Task 1: Three new CipherBoxClient methods (TDD)

- `replaceFile` (`client.ts:1287`), `restoreFileVersion` (`client.ts:1396`), and `deleteFileVersion` (`client.ts:1478`) all follow the canonical 5-step pattern wrapped in `this.withOperation(...)`: read folder from `folderTree` (throw "Folder not loaded" if missing), publish file metadata via `updateFileMetadata`, conditional folder publish, adopt `publishedChildren`/`newSequenceNumber`, and emit `folder:updated` (emissions at `client.ts:1358,1446,1532`).
- `replaceFile` mirrors the old web "6b" block: publishes the file, then touches the parent folder (bumping the FilePointer's `modifiedAt`) via `updateFolderMetadataAndPublish`, adopts the result into `folderTree`, and returns `{ prunedCids }`.
- `restoreFileVersion`/`deleteFileVersion` accept pre-resolved `fileIpnsPrivateKey` + `currentMetadata` (locked decision 2). The folder publish is conditional on a key-epoch migration; otherwise only the file IPNS publish happens and the folder sequence stays put. Both emit `folder:updated` from the read-back `folderTree` snapshot.
- None of the three methods zero `fileIpnsPrivateKey` — `updateFileMetadata` owns zeroing (T-47-01).
- New `packages/sdk/src/__tests__/client-file-ops.test.ts` asserts each method emits `folder:updated` with the correct children + sequenceNumber, advances `folderTree`, returns `prunedCids`, and throws on an unregistered parent.

### Task 2: Delete reconcileFolderState

- The `reconcileFolderState` method + its doc comment were removed from `client.ts`. Confirmed repo-wide: `grep -rc 'reconcileFolderState' packages/sdk/src apps/web/src` returns 0 everywhere (the web call-site removal was done in Plan 04).

## Verification

Shipped and merged via PR #494 (commit d17d42e5f). Phase 47 VERIFICATION.md (score 5/5, status human_needed) covers goal achievement. This summary was backfilled on 2026-06-17 to close a bookkeeping gap (plans had no matching summaries on disk).
