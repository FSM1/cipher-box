---
phase: 48-sdk-self-bootstrap-regression-fix-and-shared-folder-metadata
plan: "03"
subsystem: sdk
tags: [sdk, shared-folder, state, events, tdd]
dependency_graph:
  requires: ["48-01"]
  provides: ["REQ-3"]
  affects:
    [
      "packages/sdk/src/client.ts",
      "packages/sdk/src/types.ts",
      "packages/sdk/src/events.ts",
      "packages/sdk/src/state/shared-folder-tree.ts",
      "packages/sdk/src/index.ts",
    ]
tech_stack:
  added: []
  patterns:
    - "Sibling sharedFolderTree keyed by shareId (NOT ipnsName) — mirrors Phase-47 owned folderTree single-ownership model"
    - "Client shared methods own publish+sequence+emit, delegating the write to stateless share/shared-write.ts (publishWithCas is the one CAS engine)"
key_files:
  created:
    - packages/sdk/src/state/shared-folder-tree.ts
    - packages/sdk/src/__tests__/shared-folder-tree.test.ts
    - packages/sdk/src/__tests__/client-shared-write.test.ts
  modified:
    - packages/sdk/src/types.ts
    - packages/sdk/src/events.ts
    - packages/sdk/src/client.ts
    - packages/sdk/src/index.ts
decisions:
  - "SharedFolderState stores ipnsPrivateKey (not a full ipnsKeypair) because the shared-write functions and SharedWriteContext only need the private key for signing — matches SharedWriteContext exactly, avoids carrying an unused public key."
  - "updateSharedFile emits sharedFolder:updated with UNCHANGED children/sequence: the stateless updateSharedFile returns void and publishes only the file's own IPNS metadata (FilePointer unchanged), so there is no folder write-back — but the event still fires so consumers re-resolve the file (mirrors owned restoreFileVersion file-only emission)."
  - "Added convenience accessors hasSharedFolder/getSharedFolderState/unloadSharedFolder alongside loadSharedFolder so plan 48-04's web hook can read/seed/clear share state without reaching into internals (mirrors hasFolder/getFolderSequenceNumber on the owned path)."
metrics:
  duration: "~6 minutes"
  completed: "2026-06-16"
  tasks_completed: 3
  tasks_total: 3
  files_created: 3
  files_modified: 4
---

# Phase 48 Plan 03: Shared-folder state ownership in the SDK Summary

SDK client now owns shared-folder write state in a sibling `sharedFolderTree` keyed by `shareId`, with five `(shareId, args)` client methods that delegate to the existing `share/shared-write.ts` functions and emit a new `sharedFolder:updated` event — the contract plan 48-04 wires the web hook against.

## What Was Built

REQ-3 (SDK side): the SDK client is now the single owner of shared-folder state, mirroring the Phase-47 owned-path model but in a distinct map because shared folders carry a per-share `SharedWriteContext` and can collide on `ipnsName`.

### New contract (consumed by plan 48-04)

- `SharedFolderState` (`packages/sdk/src/types.ts`): `{ shareId, ipnsName, folderKey, ipnsPrivateKey, sequenceNumber, children, ownerPublicKey, recipientPublicKey, addShareKeysFn }` — the full SharedWriteContext surface as persistable state.
- `SharedFolderTree` (`packages/sdk/src/state/shared-folder-tree.ts`): map keyed by `shareId`; `get/set/has/delete/clear/getAll`. `set()` clones `folderKey`/`ipnsPrivateKey` so caller buffers are never zeroed; `delete()`/`clear()` zero key material (CLAUDE.md rule 9).
- `sharedFolder:updated` event (`packages/sdk/src/events.ts`): `{ type: 'sharedFolder:updated'; shareId; ipnsName; children; sequenceNumber }`.
- Client methods (`packages/sdk/src/client.ts`):
  - `loadSharedFolder(shareId, state)` — seed/register (plus `hasSharedFolder`, `getSharedFolderState`, `unloadSharedFolder`).
  - `uploadToSharedFolder(shareId, { data, fileName, mimeType? })`
  - `createSharedSubfolder(shareId, { name })`
  - `renameInSharedFolder(shareId, { itemId, newName })`
  - `deleteFromSharedFolder(shareId, { itemId })`
  - `updateSharedFile(shareId, { filePointer, newContent, getFileIpnsKeyFn })`
- Public exports of `SharedFolderState` and `SharedFolderTree` from `packages/sdk/src/index.ts`.

Each write method: reads state via `requireSharedFolder` (throws `'Shared folder not loaded'` if absent) → builds a `SharedWriteContext` from that state → delegates to the matching `share/shared-write.ts` function (whose `updateFolderMetadataAndPublish` routes through `publishWithCas` — no second retry loop) → writes `publishedChildren`/`newSequenceNumber` back → emits `sharedFolder:updated`.

## Task Commits

| Task | Name | Commit |
| ---- | ---- | ------ |
| 1 | Contracts: SharedFolderState, SharedFolderTree, sharedFolder:updated | 220bf8f9d |
| 2 | RED: tree isolation (GREEN) + client shared-write contract (RED) | a6bc822c1 |
| 3 | GREEN: client methods + loader + exports | 64e8b8967 |

## TDD Gate Compliance

- RED gate: `test(...)` commit a6bc822c1 — `client-shared-write.test.ts` failed (`loadSharedFolder`/`uploadToSharedFolder` not functions); `shared-folder-tree.test.ts` already GREEN (tree shipped in Task 1).
- GREEN gate: `feat(...)` commit 64e8b8967 — all shared suites pass.
- No REFACTOR commit needed.

## Verification

- `pnpm exec vitest run shared` (packages/sdk): 23 passed (tree 4, shared-write 17, client-shared-write 2).
- `pnpm exec tsc --noEmit -p tsconfig.json` (packages/sdk): exit 0.
- `pnpm exec eslint 'src/**/*.ts'` (packages/sdk): exit 0.
- Full sdk suite: 191 passed; 3 failures isolated to `integration.test.ts` ("live API" suite, ECONNREFUSED to localhost:3000 — pre-existing, requires a running API server, out of scope per SCOPE BOUNDARY).

Acceptance greps:

- `grep -c sharedFolderTree src/client.ts` → 13 (field + reads in all methods).
- `grep -c "withConflictRetry\|withRevocationGuard" src/client.ts` → 0 (no second retry loop).
- `SharedFolderState` + `SharedFolderTree` exported from `index.ts`.

## Deviations from Plan

### Naming

The plan suggested the verify command `pnpm --filter @cipherbox/sdk typecheck`, but `@cipherbox/sdk` has no `typecheck` script — typecheck is run via `tsc --noEmit -p tsconfig.json` (the repo-root `typecheck` orchestrates per-package `tsc`). Used the direct `tsc --noEmit` invocation; result is equivalent. Not a code change.

No auto-fixes (Rules 1-3) were required — the plan's analogs matched the codebase exactly.

## Notes for Plan 48-04

- The web hook seeds state once per resolved share via `loadSharedFolder(shareId, state)`, then calls the five `(shareId, args)` methods; `useSharedNavigation`'s `folderChildrenRef`/`sequenceNumberRef` become projections fed by the `sharedFolder:updated` event (never written from the write hook directly).
- `updateSharedFile` emits with unchanged children/sequence (file-only publish) — the projection should treat that event as a "re-resolve file" signal, not a children replacement that drops local state.
- Web consumes the BUILT `@cipherbox/sdk` dist — run the sdk build before web typecheck in 48-04 (cross-package dist staleness gotcha).

## Self-Check: PASSED

All 3 created files present on disk; all 3 task commits (220bf8f9d, a6bc822c1, 64e8b8967) present in git history.
