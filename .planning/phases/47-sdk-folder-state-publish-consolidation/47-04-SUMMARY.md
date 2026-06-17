---
phase: 47-sdk-folder-state-publish-consolidation
plan: "04"
subsystem: web
tags: [web, hooks, folder-state, file-ops, refactor]
dependency_graph:
  requires:
    - CipherBoxClient.replaceFile
    - CipherBoxClient.restoreFileVersion
    - CipherBoxClient.deleteFileVersion
  provides: [REQ-1-web-consumer-half]
  affects:
    - apps/web/src/hooks/useFileOperations.ts
    - apps/web/src/hooks/useFileVersions.ts
    - apps/web/src/lib/sdk-provider.ts
tech_stack:
  added: []
  patterns: [client-method-routing, projection-only-store, key-zeroing-at-call-site, awaited-publish-removes-race]
key_files:
  created: []
  modified:
    - apps/web/src/hooks/useFileOperations.ts
    - apps/web/src/hooks/useFileVersions.ts
    - apps/web/src/lib/sdk-provider.ts
decisions:
  - "useFileOperations.updateFile routes the '6b' folder republish through client.replaceFile and no longer calls sdkCore.updateFolderMetadataAndPublish directly (REQ-1)"
  - "useFileVersions handleRestoreVersion / handleDeleteVersion route through client.restoreFileVersion / client.deleteFileVersion (REQ-1)"
  - "The three hooks no longer write folder-state to Zustand directly — children/sequenceNumber flow only through the folder:updated subscription, closing the PR #489 desync race"
  - "The web hook resolves fileIpnsPrivateKey via getFileIpnsPrivateKey BEFORE the client call and preserves the existing finally-block fill(0) at the call site (locked decision 2, T-47-01)"
  - "Owner-path unpin of replaceFile's returned prunedCids stays in the web hook via the apps/web ipfs wrapper"
  - "reconcileFolderState call removed from ensureFolderRegistered (sdk-provider.ts) — pairs with the Plan 03 method deletion; repo-wide references now 0 (REQ-1 exit criterion)"
metrics:
  duration: "backfilled"
  completed_date: "2026-06-15"
  tasks_completed: 2
  files_changed: 3
status: complete (backfilled 2026-06-17 — plan shipped via PR #494, summary reconstructed retroactively)
---

# Phase 47 Plan 04: web hooks routed through client methods Summary

One-liner: Rewired the three folder-state-mutating web file paths through the new SDK client methods, stripped their direct sdk-core publishes and direct Zustand folder-state writes, and removed the `reconcileFolderState` call from `ensureFolderRegistered`.

## What Was Built

### Task 1: Route useFileOperations.updateFile through client.replaceFile

- The inline "6b" `updateFolderMetadataAndPublish` block plus its `.then` store writes were replaced with a single awaited `getSdkClient().replaceFile(...)` (`useFileOperations.ts:112`), capturing `{ prunedCids }`.
- The hook still resolves `fileIpnsPrivateKey` via `getFileIpnsPrivateKey` before the call and keeps its `fill(0)` finally (locked decision 2, T-47-01).
- The owner-path `prunedCids` unpin loop via the apps/web ipfs wrapper is retained. Because `replaceFile` is now awaited (not fire-and-forget), the PR #489 race is gone.

### Task 2: Route useFileVersions restore/delete + remove reconcileFolderState call

- `handleRestoreVersion` now awaits `getSdkClient().restoreFileVersion(...)` (`useFileVersions.ts:103`) and `handleDeleteVersion` awaits `getSdkClient().deleteFileVersion(...)` (`useFileVersions.ts:211`); neither publishes folder metadata directly anymore.
- The `.then` `store.updateFolderChildren`/`updateFolderSequence` folder-state writes were removed from both handlers — the `folder:updated` subscription owns them.
- `ensureFolderRegistered` in `sdk-provider.ts` no longer calls `reconcileFolderState`; it now just no-ops when the folder is already registered. Repo-wide `reconcileFolderState` references confirmed 0.

## Verification

Shipped and merged via PR #494 (commit d17d42e5f). Phase 47 VERIFICATION.md (score 5/5, status human_needed) covers goal achievement. This summary was backfilled on 2026-06-17 to close a bookkeeping gap (plans had no matching summaries on disk).
