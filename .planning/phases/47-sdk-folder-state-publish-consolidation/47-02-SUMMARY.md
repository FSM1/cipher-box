---
phase: 47-sdk-folder-state-publish-consolidation
plan: "02"
subsystem: sdk
tags: [sdk, shared-write, unpin, refactor, tdd]
dependency_graph:
  requires: [publishWithCas]
  provides: [REQ-3-shared-write-cleanup, REQ-4-shared-file-unpin]
  affects:
    - packages/sdk/src/share/shared-write.ts
tech_stack:
  added: []
  patterns: [fire-and-forget-unpin, failure-tolerant-catch, typescript-compile-as-consumer-proof]
key_files:
  created: []
  modified:
    - packages/sdk/src/share/shared-write.ts
    - packages/sdk/src/share/__tests__/shared-write.test.ts
decisions:
  - "Dropped the redundant pre-merge updatedChildren from all four shared-write return shapes; only publishedChildren remains (locked decision 3)"
  - "TypeScript compile across sdk + web is the proof no consumer relied on updatedChildren (useSharedWriteOps already read publishedChildren)"
  - "updateSharedFile now destructures prunedCids from updateFileMetadata and fire-and-forget unpins each via sdkCore.unpinFromIpfs(ctx, cid).catch — closes the shared-file pin leak (REQ-4)"
  - "Unpin is fire-and-forget; a Phase-42 server 403 for a non-owned CID is caught and logged, never thrown (T-47-04)"
metrics:
  duration: "backfilled"
  completed_date: "2026-06-15"
  tasks_completed: 2
  files_changed: 2
status: complete (backfilled 2026-06-17 — plan shipped via PR #494, summary reconstructed retroactively)
---

# Phase 47 Plan 02: shared-write cleanup Summary

One-liner: Removed the stale pre-merge `updatedChildren` from all four shared-write returns and made `updateSharedFile` unpin the `prunedCids` returned by `updateFileMetadata`, closing the shared-file storage pin leak.

## What Was Built

### Task 1: Drop updatedChildren from the four shared-write returns

- `uploadToSharedFolder`, `createSharedSubfolder`, `renameInSharedFolder`, and `deleteFromSharedFolder` no longer return `updatedChildren` — confirmed each `return { ... }` carries only `publishedChildren`, `newSequenceNumber`, and the per-function item (`filePointer`/`folderEntry`) at `shared-write.ts:227,328,366,397`.
- The local `const updatedChildren = ...` declarations that feed `children:` into `updateFolderMetadataAndPublish` are retained (`shared-write.ts:201,297,352,385`) — only the RETURN dropped it.
- Removal verified by TypeScript compile: the sole consumer (`useSharedWriteOps`) already read `publishedChildren`, so sdk build + web typecheck stayed clean (locked decision 3).

### Task 2: Unpin prunedCids in updateSharedFile (TDD)

- `updateSharedFile` now destructures `const { prunedCids } = await updateFileMetadata({ ... })` (`shared-write.ts:461`) instead of discarding the return; the stale "pre-existing Phase-42 deferred leak" comment was removed.
- It then fire-and-forget unpins each pruned CID, mirroring the owner path: `unpinFromIpfs(params.ctx, cid).catch(...)` (`shared-write.ts:484`), using the `@cipherbox/sdk-core` form (imported at `shared-write.ts:46`), not the apps/web wrapper.
- Tests in `shared-write.test.ts` assert: unpins each pruned CID, tolerates an unpin rejection without throwing (Phase-42 403 simulation), and does not unpin when `prunedCids` is empty.

## Verification

Shipped and merged via PR #494 (commit d17d42e5f). Phase 47 VERIFICATION.md (score 5/5, status human_needed) covers goal achievement. This summary was backfilled on 2026-06-17 to close a bookkeeping gap (plans had no matching summaries on disk).
