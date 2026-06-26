---
phase: 47-sdk-folder-state-publish-consolidation
plan: "05"
subsystem: web
tags: [web, store, folder-state, projection, tdd]
dependency_graph:
  requires:
    - CipherBoxClient.replaceFile
    - CipherBoxClient.restoreFileVersion
    - CipherBoxClient.deleteFileVersion
  provides: [REQ-1-store-projection-only, phase-47-full-suite-gate]
  affects:
    - apps/web/src/stores/folder.store.ts
tech_stack:
  added: []
  patterns: [projection-only-store, folder-updated-subscription, ipnsName-reverse-lookup, tdd]
key_files:
  created:
    - apps/web/src/stores/__tests__/folder.store.test.ts
  modified:
    - apps/web/src/stores/folder.store.ts
decisions:
  - "useFolderStore children + sequenceNumber are projection-only — the subscribeToSdk folder:updated/folder:loaded handler is the writer, keyed by ipnsName reverse-lookup (REQ-1)"
  - "updateFolderChildren / updateFolderSequence store actions retained — the subscription handler and legitimate non-mutation resync paths still call them; only the bypass mutation call sites were removed in Plan 04"
  - "Handler confirmed projection-only with no behavior change needed; root folder reverse-lookup verified to match (Assumption A2)"
  - "Test file named .test.ts (NOT .spec.ts) — web vitest include is src/**/*.test.ts and silently skips .spec.ts"
  - "Task 2 was the phase full-suite green gate in build order (sdk-core build/test, sdk build/test, web test, web typecheck) — no production logic changed"
metrics:
  duration: "backfilled"
  completed_date: "2026-06-15"
  tasks_completed: 2
  files_changed: 2
status: complete (backfilled 2026-06-17 — plan shipped via PR #494, summary reconstructed retroactively)
---

# Phase 47 Plan 05: useFolderStore projection-only Summary

One-liner: Locked in `useFolderStore` `children`/`sequenceNumber` as projection-only state driven by the `folder:updated` subscription, added the missing `folder.store.test.ts` proving the projection handler is the writer, and ran the phase full-suite green gate.

## What Was Built

### Task 1: folder.store projection tests + projection-only handler (TDD)

- New `apps/web/src/stores/__tests__/folder.store.test.ts` (`.test.ts`, so web vitest actually runs it) proves the `subscribeToSdk` handler projects state: a `folder:updated` event writes `children` + `sequenceNumber` into the matched store entry, the root folder reverse-lookup matches (Assumption A2), `folder:loaded` also projects, and an unknown `ipnsName` is a no-op.
- The `subscribeToSdk` handler in `folder.store.ts` was confirmed projection-only — the `folder:loaded`/`folder:updated` cases (`folder.store.ts:208-209`) do the `Object.values(folders).find(f => f.ipnsName === event.ipnsName)` reverse-lookup then call the existing `updateFolderChildren`/`updateFolderSequence` actions. No new store actions or signature changes.
- The `updateFolderChildren`/`updateFolderSequence` actions remain — used by the subscription handler and legitimate non-mutation resync paths (root re-sync, resyncFolder), which were intentionally out of scope in Plan 04.

### Task 2: Full-suite green gate

- Ran the phase gate in build order (sdk-core build to sdk build to all three vitest suites to web typecheck) and confirmed the phase exit criteria: `publishWithCas` wired into folder + file, `baseChildren` encapsulated, `updatedChildren` dropped from shared-write returns, `prunedCids` unpinned in `updateSharedFile`, the three client methods own `folder:updated`, the folder.store projection tested, and repo-wide `reconcileFolderState` references at 0.

## Verification

Shipped and merged via PR #494 (commit d17d42e5f). Phase 47 VERIFICATION.md (score 5/5, status human_needed) covers goal achievement. This summary was backfilled on 2026-06-17 to close a bookkeeping gap (plans had no matching summaries on disk).
